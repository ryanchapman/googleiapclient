package googleiapclient

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"

type serviceAccount struct {
	ProjectID     string `json:"project_id"`
	PrivateKey    string `json:"private_key"`
	ClientEmail   string `json:"client_email"`
	ClientID      string `json:"client_id"`
	RSAPrivateKey *rsa.PrivateKey
}

type IAPClient struct {
	serviceAccount
	envVarName string // env variable which contains base64 encoded JSON service account
}

// Create a new IAPClient with credentials that are base64 encoded in an environment
// variable named envVarName
//
// For example, if you have a service account file from GCP named proj.adf102a21567.json:
//
//    export GOOGLE_CREDS="$(cat proj.adf102a21567.json | base64)"
//    ./goprogramUsingThisLibrary
//
// in program code:
//    iapClient := NewIAPClient("GOOGLE_CREDS")
//
func NewIAPClient(envVarName string) *IAPClient {
	return &IAPClient{envVarName: envVarName}
}

func (i *IAPClient) loadCredentials() error {
	if i != nil && i.ProjectID != "" && i.PrivateKey != "" && i.ClientEmail != "" &&
		i.ClientID != "" && i.RSAPrivateKey != nil {
		return nil // already loaded
	}
	credsBase64 := os.Getenv(i.envVarName)
	if credsBase64 == "" {
		msg := "could not find service account credentials in the environment variable "
		msg += fmt.Sprintf("named %s, got %s=\"%s\"", i.envVarName, i.envVarName, credsBase64)
		return fmt.Errorf("%s", msg)
	}
	credsBytes, err := base64.StdEncoding.DecodeString(credsBase64)
	if err != nil {
		log.Fatalf("Could not base64 decode contents of env var %s: %v", i.envVarName, err)
	}
	// to minimize lock time, unmarshal, then take lock to copy creds to global struct
	tmpCreds := &serviceAccount{}
	err = json.Unmarshal(credsBytes, tmpCreds)
	if err != nil {
		log.Fatalf("Could not unmarshal credentials from env var %s: %v", i.envVarName, err)
	}
	// PrivateKey is in PEM format. Convert to rsa.PrivateKey
	blk, _ := pem.Decode([]byte(tmpCreds.PrivateKey))
	if blk == nil {
		return fmt.Errorf("could not decode PrivateKey in service account credentials: not in PEM format")
	}
	if blk.Type != "PRIVATE KEY" {
		msg := "could not decode PrivateKey in service account credentials: "
		msg += "should start with \"-----BEGIN PRIVATE KEY-----\""
		return fmt.Errorf("%s", msg)
	}
	// try PKCS8
	privKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		// try PKCS1
		privKey, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil || privKey == nil {
			msg := "could not decode PrivateKey in service account credentials, "
			msg += "should be PEM in PKCS8 or PKCS1 format: "
			msg += fmt.Sprintf("%s", err)
			return fmt.Errorf("%s", msg)
		}
	}
	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		msg := "could not decode PrivateKey in service account credentials: "
		msg += fmt.Sprintf("could not cast to (*rsa.PrivateKey): %s", err)
		return fmt.Errorf("%s", msg)
	}
	i.ProjectID = tmpCreds.ProjectID
	i.PrivateKey = tmpCreds.PrivateKey
	i.RSAPrivateKey = rsaPrivKey
	i.ClientEmail = tmpCreds.ClientEmail
	i.ClientID = tmpCreds.ClientID
	return nil // no error
}

// Generate a JWT bearer token that can be passed to a IAP protected endpoint
// which has the specified target audience (OAuth Client ID).
//
// You can find the target audience by going to
// GCP Console > Security > Identity Aware Proxy, click three dots beside your load balancer,
// Edit OAuth Client, Client ID
//
// It will look something like
//    "823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com"
// (without http:// or https://)
//
// Another method which works as of this writing is to curl a IAP protected
// endpoint and look at the redirect:
//
//    $ curl -v https://test.initech.com/nonexist
//    > GET /nonexist HTTP/1.1
//    [...]
//
//    < HTTP/1.1 302 Found
//    [...]
//    < Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com&response_type=code&scope=openid+email&redirect_uri=https://test.initech.com/_gcp_gatekeeper/authenticate&state=XXXXXXX
//    < X-Goog-IAP-Generated-Response: true
//    < Content-Length: 0
//    [...]
//
// The returned JWT token is good for a period of time.  It is your responsibilty to
// check the expiration and request a new JWT token before the old one expires.
//
// Once you have the JWT token, you can make requests to the IAP protected endpoint by passing the JWT
// as a bearer token.  For example:
//
//    iapClient := NewIAPClient("GOOGLE_CREDS")
//    token, err := iapClient.JWTToken("823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com")
//    if err != nil {
//            log.Panicf("Could not get JWT token: %+v", err)
//    }
//
//    url := "https://test.initech.com"
//    req, err := http.NewRequest("GET", url, nil)
//    if err != nil {
//            log.Panicf("Could not create GET request to %s: %+v", url, err)
//    }
//
//    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token)
//    client := http.Client{}
//    resp, err := client.Do(req)
//    if resp != nil {
//            defer resp.Body.Close()
//    }
//    /* handle response */
//
func (i *IAPClient) JWTToken(targetAudience string) (string, error) {
	err := i.loadCredentials()
	if err != nil {
		return "", err
	}
	sigOpts := (&jose.SignerOptions{}).WithType("JWT")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.RSAPrivateKey}, sigOpts)
	if err != nil {
		return "", fmt.Errorf("could not create NewSigner: %s", err)
	}

	type customClaims struct {
		Issuer         string          `json:"iss,omitempty"`
		Audience       string          `json:"aud,omitempty"`
		Expiry         jwt.NumericDate `json:"exp,omitempty"`
		IssuedAt       jwt.NumericDate `json:"iat,omitempty"`
		TargetAudience string          `json:"target_audience,omitempty"`
	}

	claims := customClaims{
		Issuer:         i.ClientEmail,
		Audience:       TOKEN_URL,
		Expiry:         jwt.NewNumericDate(time.Now().UTC().Add(1 * time.Hour)),
		IssuedAt:       jwt.NewNumericDate(time.Now()),
		TargetAudience: targetAudience,
	}

	rawJwt, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	params := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
	params += rawJwt
	reqBody := []byte(params)
	req, err := http.NewRequest("POST", TOKEN_URL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("While building request to contact %s for token, got err=%+v", TOKEN_URL, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("While contacting %s to get token, got resp=%+v, err=%+v", TOKEN_URL, resp, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("While contacting %s for token, could not read bytes from response, err=%+v", TOKEN_URL, err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("While contacting %s for token, got non-200 response (%d), body=%s", TOKEN_URL, resp.StatusCode, body)
	}
	type googleOauth2TokenResponse struct {
		IDToken string `json:"id_token"`
	}
	tokenResp := new(googleOauth2TokenResponse)
	err = json.Unmarshal([]byte(body), tokenResp)
	if err != nil || tokenResp == nil {
		return "", fmt.Errorf("While contacting %s for token, could not unmarshal json response, err=%+v", TOKEN_URL, err)
	}
	return tokenResp.IDToken, nil
}

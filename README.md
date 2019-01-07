# googleiapclient

A golang library which provides a way to use a service account to programmatically access
resources behind Google Cloud's Identity Aware Proxy.

[![Build Status](https://travis-ci.org/ryanchapman/googleiapclient.svg?branch=master)](https://travis-ci.org/ryanchapman/googleiapclient)

## Documentation

[https://godoc.org/github.com/ryanchapman/googleiapclient](https://godoc.org/github.com/ryanchapman/googleiapclient)

## Usage

1. Create a service account in the GCP console and download credentials in JSON format (the P12 option does not work).

2. Encode the json file you downloaded and place in an environment variable:

    ```
    export GOOGLE_CREDS="$(cat rchapman-f9bcc275ce03.json | base64)"
    ```

3. Get your OAuth client ID, which can be found at
       GCP Console > Security > Identity Aware Proxy, click three dots beside your load balancer, Edit OAuth Client, Client ID

   You can also curl a IAP protected endpoint and look at the redirect to find the client ID:

    ```
    $ curl -v https://test.initech.com/nonexist
    > GET /nonexist HTTP/1.1
    [...]
    
    < HTTP/1.1 302 Found
    [...]
    < Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com&response_type=code&scope=openid+email&redirect_uri=https://test.initech.com/_gcp_gatekeeper/authenticate&state=XXXXXXX
    < X-Goog-IAP-Generated-Response: true
    < Content-Length: 0
    [...]
    ```
       
4. Add code to your program to use the library.  In this example, `GOOGLE_CREDS` is the environment variable
   which contains the base64 encoded service account credentials in json format.  The parameter to
   `JWTToken()` is the OAuth client ID  you found in step #3.  The OAuth client ID will be encoded as `target_audience` before it is sent to the Google OAuth service to obtain a JWT token.

    ```
    import (
           "github.com/ryanchapman/googleiapclient"
    )
    
    func main() {
            // get service account from environment variable   GOOGLE_CREDS
            iapClient := googleiapclient.NewIAPClient("GOOGLE_CREDS")
            token, err := iapClient.JWTToken("823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com")
            if err != nil {
                    log.Panicf("Could not get JWT token: %+v", err)
            }
    
            fmt.Printf("%s\n", token)
            
            url := "https://test.initech.com"
            req, err := http.NewRequest("GET", url, nil)
            if err != nil {
                    log.Panicf("Could not create GET request to %s: %+v", url, err)
            }
    
            req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
            client := http.Client{}
            resp, err := client.Do(req)
            if resp != nil {
                    defer resp.Body.Close()
            }
            /* handle response */
    }
    ```

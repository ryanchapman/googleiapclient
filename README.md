# googleiapclient

A golang library and reference command line tool which provides a way to use a service account to programmatically access
resources behind Google Cloud's Identity Aware Proxy.

[![Build Status](https://travis-ci.org/ryanchapman/googleiapclient.svg?branch=master)](https://travis-ci.org/ryanchapman/googleiapclient)
[![GoDoc](https://pkg.go.dev/github.com/ryanchapman/googleiapclient?tab=doc)](https://pkg.go.dev/github.com/ryanchapman/googleiapclient?tab=doc)

## Documentation

[https://pkg.go.dev/github.com/ryanchapman/googleiapclient?tab=doc](https://pkg.go.dev/github.com/ryanchapman/googleiapclient?tab=doc)

## Library Usage

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
   which contains the base64 encoded service account credentials in json format.  The first parameter to
   `JWTToken()` is the OAuth client ID  you found in step #3.  The OAuth client ID will be encoded as `target_audience` before it is sent to the Google OAuth service to obtain a JWT token.

    ```
    import (
           "github.com/ryanchapman/googleiapclient"
    )
    
    func main() {
            requestedExpiration := time.Duration(1 * time.Hour)
            // get service account from environment variable   GOOGLE_CREDS
            iapClient := googleiapclient.NewIAPClient("GOOGLE_CREDS", requestedExpiration)
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
    
5. The iapclient struct will automatically renew tokens; you just need to call JWTToken() right before you need to use the token to get the latest.

6. Call `iapClient.Done()` when you want iapclient to stop updating tokens.

## Command Line Tool Usage

1. Create a service account in the GCP console and download credentials in JSON format (the P12 option does not work).

2. Grant the service account access to your IAP protected load balancer(s) by giving the service account the role "IAP-secured Web App User" in your GCP project.

3. Compile geniaptoken by running `./make.bash geniaptoken` 

4. Run geniaptoken to generate a JWT (JSON Web Token) that can be used with the GCP load balancer  (see Library Usage, step #3 above for help with finding your OAuth Client ID) `./geniaptoken --google-creds-file=creds.json --requested-expiration=1h --oauth-client-id=823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com`

5. The geniaptoken tool will output a JWT as an `Authorization` header. For example, `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`.  You can add that header to your http request to your IAP protected load balancer.

6. Example run:

```
$ Dec 29 06:34:11.N +01 make.bash[7460]: Compiling geniaptoken
Dec 29 06:34:11.N +01 make.bash[7460]: go build -o geniaptoken cmd/geniaptoken/main.go
Dec 29 06:34:12.N +01 make.bash[7460]: go build -o geniaptoken cmd/geniaptoken/main.go returned 0
Dec 29 06:34:12.N +01 make.bash[7460]: Compiling geniaptoken: done

$ curl -D- -s -H "$(./geniaptoken --google-creds-file=onx-staging-qa-iap.json --requested-expiration=1h --oauth-client-id=823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com)" https://test.initech.com
HTTP/2 200
[...]
```

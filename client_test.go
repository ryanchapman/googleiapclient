package googleiapclient

// run tests with:
//
//    GOOGLE_CREDS="$(cat rchapman-f9bcc275ce03.json | base64)" go test
//

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const audience = "823926513327-pr0714rqtdb223bahl0nq2jcd4ur79ec.apps.googleusercontent.com"

func TestClient(t *testing.T) {
	assert := assert.New(t)
	iapClient := NewIAPClient("GOOGLE_CREDS")
	// JWTToken() should make a call to the Google OAuth2 service to get a bearer token
	requestedExpiry := time.Now().UTC().Add(1 * time.Hour)
	token, tokenWillAutorenew, err := iapClient.JWTToken(audience, requestedExpiry)
	assert.Equal(nil, err, "JWTToken(audience) should have returned err=nil")
	assert.NotEqual("", token, "JWTToken(audience) should have returned token != \"\"")
	// TODO(rchapman): test that expiration is after requestedExpiry
	assert.Equal(false, tokenWillAutorenew, "JWTToken() returned that token will auto-renew, which is not yet implemented")
	// TODO(rchapman): we don't currently have a IAP enabled load balancer to test against
	//                 mainly because GCP LBs have a monthly cost associated with them.
}

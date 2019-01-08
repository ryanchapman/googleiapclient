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
	iapClient := NewIAPClient("GOOGLE_CREDS", 60*time.Minute)
	token, err := iapClient.JWTToken(audience)
	time.Sleep(2 * time.Second) // allow time for background token refresh to start
	assert.Equal(true, iapClient.BackgroundTokenRefreshRunning(), "JWT Token background refresh should be running")
	currentExpiration := iapClient.CurrentJWTTokenExpiration()
	nowPlus60Min := time.Now().UTC().Add(60 * time.Minute)
	tolerance := 10 * time.Second
	assert.WithinDuration(nowPlus60Min, currentExpiration, tolerance, "Current JWT Token should expire within 60 minutes (+/- 10s)")
	assert.Equal(nil, err, "JWTToken(audience) should have returned err=nil")
	assert.NotEqual("", token, "JWTToken(audience) should have returned token != \"\"")
	// TODO(rchapman): we don't currently have a IAP enabled load balancer to test against
	//                 mainly because GCP LBs have a monthly cost associated with them.
}

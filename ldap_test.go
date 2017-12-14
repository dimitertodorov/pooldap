package pooldap_test

import (
	"github.com/dimitertodorov/pooldap"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

var testUsers = []string{
	"zoidberg",
	"bender",
	"leela",
	"hermes",
	"fry",
	"professor",
}

var testClient *pooldap.Client
var testConfig pooldap.LdapConfig

func init() {
	testClient = InitTestConfig()
}

func InitTestConfig() (testClient *pooldap.Client) {
	testViper := viper.New()
	testViper.SetConfigFile("ldap.test.yml")

	// If a config file is found, read it in.
	if err := testViper.ReadInConfig(); err != nil {
		log.Fatalf(`Config file not found because "%s"`, err)
	}
	if err := testViper.Unmarshal(&testConfig); err != nil {
		log.Fatalf("Could not read config because %s.", err)
	}

	testClient, err := pooldap.NewClient(testConfig, 5, 5, 5, 6, 30*time.Second)
	if err != nil {
		log.Fatalf("Could not initialize client pool %s.", err)
	}

	return
}

func TestLdapConfig(t *testing.T) {
	assert.NotNil(t, testClient)
	assert.Equal(t, "xubu", testClient.Config.Host)
	assert.Equal(t, 389, testClient.Config.Port)
}

func TestClient_GetUser(t *testing.T) {
	user, err := testClient.GetUser("zoidberg")
	assert.NoError(t, err)
	assert.Regexp(t, "(?i)John A. Zoidberg", user["cn"])
}

func TestClient_Authenticate(t *testing.T) {
	valid, user, err := testClient.Authenticate("zoidberg", "zoidberg")
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.Regexp(t, "(?i)John A. Zoidberg", user["cn"])
}

func TestClient_AuthenticateBadPassword(t *testing.T) {
	valid, user, err := testClient.Authenticate("zoidberg", "evil")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Regexp(t, "(?i)John A. Zoidberg", user["cn"])
}

func TestClient_GetUserGroups(t *testing.T) {
	groups, err := testClient.GetUserGroups("fry")
	assert.NoError(t, err)
	group, ok := groups["ship_crew"]
	assert.True(t, ok)
	assert.Equal(t, group, "cn=ship_crew,ou=people,dc=planetexpress,dc=com")
}

//Simple Multithreaded test to catch any race conditions. Locks are kept on LdapClient
func TestClient_GetUser_Threaded(t *testing.T) {
	var wg sync.WaitGroup
	var loopTimes = 222
	wg.Add(loopTimes * len(testUsers))
	returnChannel := make(chan (map[string]interface{}), loopTimes*len(testUsers))
	for i := 0; i < loopTimes; i++ {
		for _, user := range testUsers {
			go func(u string) {
				defer wg.Done()
				valid, modelUser, err := testClient.Authenticate(u, u)
				returnChannel <- map[string]interface{}{
					"valid": valid,
					"model": modelUser,
					"err":   err,
					"user":  u,
				}

			}(user)
		}
	}

	wg.Wait()
	close(returnChannel)
	for tr := range returnChannel {
		assert.Equal(t, tr["user"], tr["model"].(map[string]interface{})["uid"])
	}
}

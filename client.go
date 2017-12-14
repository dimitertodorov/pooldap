package pooldap

import (
	"crypto/tls"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v2"
	"time"
)

type Client struct {
	Config             LdapConfig
	ClientCertificates []tls.Certificate // Adding client certificates
	logger             *log.Logger
	searchPool         Pool
	bindPool           Pool
}

func NewClient(config LdapConfig, initialSearchConns, maxSearchConns, initialBindConns, maxBindConns int, refreshInterval time.Duration) (*Client, error) {
	ldapClient := &Client{
		Config: config,
	}
	err := ldapClient.InitClientPool(initialSearchConns, maxSearchConns, initialBindConns, maxBindConns, refreshInterval)
	return ldapClient, err
}

func clientPoolFactory(lc *Client, poolType PoolType) (ldap.Client, error) {
	var l *ldap.Conn
	var err error
	address := fmt.Sprintf("%s:%d", lc.Config.Host, lc.Config.Port)
	if !lc.Config.UseSSL {
		l, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		// Reconnect with TLS
		if !lc.Config.SkipTLS {
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				return nil, err
			}
		}
	} else {
		config := &tls.Config{
			InsecureSkipVerify: lc.Config.InsecureSkipVerify,
			ServerName:         lc.Config.ServerName,
		}
		if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
			config.Certificates = lc.ClientCertificates
		}
		l, err = ldap.DialTLS("tcp", address, config)
		if err != nil {
			return nil, err
		}
	}
	if poolType == SharedPool {
		if lc.Config.BindDN != "" && lc.Config.BindPassword != "" {
			l.Bind(lc.Config.BindDN, lc.Config.BindPassword)
		}
	}
	return l, nil
}

func (c *Client) InitClientPool(initialSearchConns, maxSearchConns, initialBindConns, maxBindConns int, refreshInterval time.Duration) error {
	var searchPool Pool
	var bindPool Pool
	var err error

	searchPool, err = NewChannelPool(initialSearchConns, maxSearchConns, SharedPool, clientPoolFactory, c, []uint8{200}, refreshInterval)
	if err != nil {
		return err
	}

	bindPool, err = NewChannelPool(initialBindConns, maxBindConns, BindPool, clientPoolFactory, c, []uint8{200}, refreshInterval)
	if err != nil {
		return err
	}

	c.searchPool = searchPool
	go c.searchPool.RefillPool()
	c.bindPool = bindPool
	go c.bindPool.RefillPool()
	return nil
}

func (lc *Client) GetUser(username string) (userAttributes map[string]interface{}, err error) {
	userAttributes = make(map[string]interface{})
	attributes := append(lc.Config.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Config.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.Config.UserFilter, username),
		attributes,
		nil,
	)
	conn, err := lc.searchPool.Get()
	defer conn.Close()
	if err != nil {
		conn.AutoClose(err)
		return
	}

	sr, err := conn.Search(searchRequest)
	if err != nil {
		conn.AutoClose(err)
		return
	}

	if len(sr.Entries) < 1 {
		err = ErrNotFound
		return
	}

	if len(sr.Entries) > 1 {
		err = ErrNotUnique
		return
	}

	for _, attr := range lc.Config.Attributes {
		userAttributes[attr] = sr.Entries[0].GetAttributeValue(attr)

	}
	userAttributes["dn"] = sr.Entries[0].DN

	return
}

func (lc *Client) Authenticate(username, password string) (valid bool, userAttributes map[string]interface{}, err error) {
	userAttributes, err = lc.GetUser(username)
	if err != nil {
		return
	}

	bindConn, err := lc.bindPool.Get()
	defer bindConn.Close()
	if err != nil {
		return
	}
	userDistinguishedName, ok := userAttributes["dn"]
	if !ok {
		err = ErrDnNotFound
		return
	}
	// Bind as the user to verify their password
	err = bindConn.Bind(userDistinguishedName.(string), password)
	if err != nil {
		//Close this connection if the
		bindConn.AutoClose(err)
		return false, userAttributes, err
	}

	valid = true
	return
}

func (lc *Client) GetUserGroups(username string) (groups map[string]string, err error) {
	userAttributes, err := lc.GetUser(username)
	if err != nil {
		return
	}

	memberAttribute, ok := userAttributes[lc.Config.GroupMemberAttribute]
	if !ok {
		err = errors.Wrap(ErrAttributeNotFound, lc.Config.GroupMemberAttribute)
		return
	}

	filter := fmt.Sprintf(lc.Config.GroupFilter, ldap.EscapeFilter(memberAttribute.(string)))
	searchRequest := ldap.NewSearchRequest(
		lc.Config.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{lc.Config.GroupNameAttribute}, // can it be something else than "cn"?
		nil,
	)

	conn, err := lc.searchPool.Get()
	defer conn.Close()
	if err != nil {
		conn.AutoClose(err)
		return
	}

	sr, err := conn.Search(searchRequest)
	if err != nil {
		conn.AutoClose(err)
		return
	}

	groups = make(map[string]string)
	for _, entry := range sr.Entries {
		groupName := entry.GetAttributeValue(lc.Config.GroupNameAttribute)
		groupDn := entry.DN
		groups[groupName] = groupDn
	}

	return
}

func newLogger(lc *Client) *log.Logger {
	var (
		err    error
		logger = log.New()
	)
	logger.Level, err = log.ParseLevel(lc.Config.LogLevel)
	if err != nil {
		logger.Errorf("Couldn't parse log level: %s", lc.Config.LogLevel)
		logger.Level = log.InfoLevel
	}

	return logger
}

func (lc *Client) SetLogger(logger *log.Logger) {
	lc.logger = logger
	return
}

func (lc *Client) GetLogger() *log.Logger {
	if lc.logger == nil {
		lc.logger = newLogger(lc)
	}

	return lc.logger
}

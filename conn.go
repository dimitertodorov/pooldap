package pooldap

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v2"
	"time"
)

// PoolConn implements Client to override the Close() method
type PoolConn struct {
	Conn     ldap.Client
	c        *channelPool
	unusable bool
	closeAt  []uint8
}

func (p *PoolConn) Start() {
	p.Conn.Start()
}

// Close() puts the given connects back to the pool instead of closing it.
func (p *PoolConn) Close() {
	if p.unusable {
		p.GetLogger().Infof("Closing unusable connection")
		if p.Conn != nil {
			p.Conn.Close()
		}
		conn, _ := p.c.NewConn()
		p.c.put(conn.Conn)
		return
	}
	p.c.put(p.Conn)
}

func (p *PoolConn) SimpleBind(simpleBindRequest *ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error) {
	return p.Conn.SimpleBind(simpleBindRequest)
}

func (p *PoolConn) Bind(username, password string) error {
	return p.Conn.Bind(username, password)
}

// MarkUnusable() marks the connection not usable any more, to let the pool close it
// instead of returning it to pool.
func (p *PoolConn) MarkUnusable() {
	p.unusable = true
}

func (p *PoolConn) AutoClose(err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("rescued panic in (p *PoolConn) AutoClose %s", r)
		}
	}()
	for _, code := range p.closeAt {
		if ldap.IsErrorWithCode(err, code) {
			p.GetLogger().Debugf("Marking LDAP Connection as Unusable due to code %d", code)
			p.unusable = true
			return
		}
	}
}

func (p *PoolConn) SetTimeout(t time.Duration) {
	p.Conn.SetTimeout(t)
}

func (p *PoolConn) Add(addRequest *ldap.AddRequest) error {
	return p.Conn.Add(addRequest)
}

func (p *PoolConn) Del(delRequest *ldap.DelRequest) error {
	return p.Conn.Del(delRequest)
}

func (p *PoolConn) Modify(modifyRequest *ldap.ModifyRequest) error {
	return p.Conn.Modify(modifyRequest)
}

func (p *PoolConn) Compare(dn, attribute, value string) (bool, error) {
	return p.Conn.Compare(dn, attribute, value)
}

func (p *PoolConn) PasswordModify(passwordModifyRequest *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return p.Conn.PasswordModify(passwordModifyRequest)
}

func (p *PoolConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return p.Conn.Search(searchRequest)
}
func (p *PoolConn) SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return p.Conn.SearchWithPaging(searchRequest, pagingSize)
}

func (p *PoolConn) GetLogger() *log.Logger {
	return p.c.GetLogger()
}

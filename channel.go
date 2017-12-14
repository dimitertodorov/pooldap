package pooldap

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"sync"

	"gopkg.in/ldap.v2"
	"time"
)

type PoolType int

const (
	// Shared is for searching the directory.
	// Factory connections will be bound on initializaytion
	SharedPool PoolType = iota
	// BindPool is to be used for authenticating users
	BindPool
)

// channelPool implements the Pool interface based on buffered channels.
type channelPool struct {
	// storage for our net.Conn connections
	mu    sync.Mutex
	conns chan ldap.Client

	name        string
	aliveChecks bool

	// net.Conn generator
	factory PoolFactory
	closeAt []uint8

	//Parent
	parentClient *Client

	//Type
	poolType PoolType

	// Logger
	logger *log.Logger

	//Caps
	initialConnections int
	maxConnections     int

	// Refill Timer
	refreshInterval time.Duration
}

// PoolFactory is a function to create new connections.
type PoolFactory func(*Client, PoolType) (ldap.Client, error)

// NewChannelPool returns a new pool based on buffered channels with an initial
// capacity and maximum capacity. Factory is used when initial capacity is
// greater than zero to fill the pool. A zero initialCap doesn't fill the Pool
// until a new Get() is called. During a Get(), If there is no new connection
// available in the pool, a new connection will be created via the Factory()
// method.
//
// closeAt will automagically mark the connection as unusable if the return code
// of the call is one of those passed, most likely you want to set this to something
// like
//   []uint8{ldap.LDAPResultTimeLimitExceeded, ldap.ErrorNetwork}
func NewChannelPool(initialCap, maxCap int, poolType PoolType, factory PoolFactory, client *Client, closeAt []uint8, refreshInterval time.Duration) (Pool, error) {
	if initialCap < 0 || maxCap <= 0 || initialCap > maxCap {
		return nil, errors.New("invalid capacity settings")
	}

	c := &channelPool{
		conns:              make(chan ldap.Client, maxCap),
		poolType:           poolType,
		factory:            factory,
		closeAt:            closeAt,
		aliveChecks:        false,
		parentClient:       client,
		initialConnections: initialCap,
		maxConnections:     maxCap,
		refreshInterval:    refreshInterval,
	}

	// create initial connections, if something goes wrong,
	// just close the pool error out.
	for i := 0; i < initialCap; i++ {
		conn, err := factory(c.parentClient, c.poolType)
		if err != nil {
			c.Close()
			return nil, errors.New("factory is not able to fill the pool: " + err.Error())
		}
		c.conns <- conn
	}

	return c, nil
}

func (c *channelPool) AliveChecks(on bool) {
	c.mu.Lock()
	c.aliveChecks = on
	c.mu.Unlock()
}

func (c *channelPool) getConns() chan ldap.Client {
	c.mu.Lock()
	conns := c.conns
	c.mu.Unlock()
	return conns
}

// Get implements the Pool interfaces Get() method. If there is no new
// connection available in the pool, a new connection will be created via the
// Factory() method.
func (c *channelPool) Get() (*PoolConn, error) {
	conns := c.getConns()
	if conns == nil {
		return nil, ErrClosed
	}

	// wrap our connections with our ldap.Client implementation (wrapConn
	// method) that puts the connection back to the pool if it's closed.
	select {
	case conn := <-conns:
		if conn == nil {
			return nil, ErrClosed
		}
		if !c.aliveChecks || isAlive(conn) {
			return c.wrapConn(conn, c.closeAt), nil
		}

		c.GetLogger().Infof("connection dead\n")
		conn.Close()
		return c.NewConn()
	}
}

func isAlive(conn ldap.Client) bool {
	_, err := conn.Search(&ldap.SearchRequest{BaseDN: "", Scope: ldap.ScopeBaseObject, Filter: "(&)", Attributes: []string{"1.1"}})
	return err == nil
}

func (c *channelPool) NewConn() (*PoolConn, error) {
	conn, err := c.factory(c.parentClient, c.poolType)
	if err != nil {
		c.GetLogger().Errorf("failed to create NewConn for pooldap.channelPool %s", err.Error())
		return nil, err
	}
	return c.wrapConn(conn, c.closeAt), nil
}

// put puts the connection back to the pool. If the pool is full or closed,
// conn is simply closed. A nil conn will be rejected.
func (c *channelPool) put(conn ldap.Client) {
	if conn == nil {
		c.GetLogger().Debug("ldap connection is nil. recreating")
		pConn, err := c.NewConn()
		if err != nil {
			return
		}
		conn = pConn.Conn
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conns == nil {
		// pool is closed, close passed connection
		conn.Close()
		return
	}

	// put the resource back into the pool. If the pool is full, this will
	// block and the default case will be executed.
	select {
	case c.conns <- conn:
		return
	default:
		// pool is full, close passed connection
		conn.Close()
		return
	}
}

func (c *channelPool) Close() {
	c.mu.Lock()
	conns := c.conns
	c.conns = nil
	c.factory = nil
	c.mu.Unlock()

	if conns == nil {
		return
	}

	close(conns)
	for conn := range conns {
		conn.Close()
	}
	return
}

func (c *channelPool) Len() int { return len(c.getConns()) }

func (c *channelPool) wrapConn(conn ldap.Client, closeAt []uint8) *PoolConn {
	p := &PoolConn{c: c, closeAt: closeAt}
	p.Conn = conn
	return p
}

func (c *channelPool) GetLogger() *log.Logger {
	return c.parentClient.GetLogger()
}

func (c *channelPool) RefillPool() {
	for {
		time.Sleep(c.refreshInterval)
		c.GetLogger().Info("refreshing LDAP connections")
		for i := c.Len(); i < c.initialConnections; i++ {
			conn, err := c.NewConn()
			if err != nil {
				conn.MarkUnusable()
				conn.Close()
				c.GetLogger().Error("could not refresh connection")
			} else {
				c.put(conn.Conn)
			}

		}
	}
}

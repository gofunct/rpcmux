package rpcmux

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Matcher func(io.Reader) bool

type MatchWriter func(io.Writer, io.Reader) bool

type ErrorHandler func(error) bool

var _ net.Error = ErrNotMatched{}

type ErrNotMatched struct {
	c net.Conn
}

func (e ErrNotMatched) Error() string {
	return fmt.Sprintf("mux: connection %v not matched by an matcher",
		e.c.RemoteAddr())
}

func (e ErrNotMatched) Temporary() bool { return true }

func (e ErrNotMatched) Timeout() bool { return false }

type errListenerClosed string

func (e errListenerClosed) Error() string   { return string(e) }
func (e errListenerClosed) Temporary() bool { return false }
func (e errListenerClosed) Timeout() bool   { return false }

var ErrListenerClosed = errListenerClosed("mux: listener closed")

// for readability of readTimeout
var noTimeout time.Duration

// New instantiates a new connection multiplexer.
func New(l net.Listener) *rpcMux {
	return &rpcMux{
		root:        l,
		bufLen:      1024,
		errh:        func(_ error) bool { return true },
		donec:       make(chan struct{}),
		readTimeout: noTimeout,
	}
}

// rpcMux is a multiplexer for network connections.
type RPrpcMux interface {
	Match(...Matcher) net.Listener
	MatchWithWriters(...MatchWriter) net.Listener
	Serve() error
	HandleError(ErrorHandler)
	SetReadTimeout(time.Duration)
}

type matchersListener struct {
	ss []MatchWriter
	l  muxListener
}

type rpcMux struct {
	root        net.Listener
	bufLen      int
	errh        ErrorHandler
	donec       chan struct{}
	sls         []matchersListener
	readTimeout time.Duration
}

func matchersToMatchWriters(matchers []Matcher) []MatchWriter {
	mws := make([]MatchWriter, 0, len(matchers))
	for _, m := range matchers {
		cm := m
		mws = append(mws, func(w io.Writer, r io.Reader) bool {
			return cm(r)
		})
	}
	return mws
}

func (m *rpcMux) Match(matchers ...Matcher) net.Listener {
	mws := matchersToMatchWriters(matchers)
	return m.MatchWithWriters(mws...)
}

func (m *rpcMux) MatchWithWriters(matchers ...MatchWriter) net.Listener {
	ml := muxListener{
		Listener: m.root,
		connc:    make(chan net.Conn, m.bufLen),
	}
	m.sls = append(m.sls, matchersListener{ss: matchers, l: ml})
	return ml
}

func (m *rpcMux) SetReadTimeout(t time.Duration) {
	m.readTimeout = t
}

func (m *rpcMux) Serve() error {
	var wg sync.WaitGroup

	defer func() {
		close(m.donec)
		wg.Wait()

		for _, sl := range m.sls {
			close(sl.l.connc)
			// Drain the connections enqueued for the listener.
			for c := range sl.l.connc {
				_ = c.Close()
			}
		}
	}()

	for {
		c, err := m.root.Accept()
		if err != nil {
			if !m.handleErr(err) {
				return err
			}
			continue
		}

		wg.Add(1)
		go m.serve(c, m.donec, &wg)
	}
}

func (m *rpcMux) serve(c net.Conn, donec <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	muc := newMuxConn(c)
	if m.readTimeout > noTimeout {
		_ = c.SetReadDeadline(time.Now().Add(m.readTimeout))
	}
	for _, sl := range m.sls {
		for _, s := range sl.ss {
			matched := s(muc.Conn, muc.startSniffing())
			if matched {
				muc.doneSniffing()
				if m.readTimeout > noTimeout {
					_ = c.SetReadDeadline(time.Time{})
				}
				select {
				case sl.l.connc <- muc:
				case <-donec:
					_ = c.Close()
				}
				return
			}
		}
	}

	_ = c.Close()
	err := ErrNotMatched{c: c}
	if !m.handleErr(err) {
		_ = m.root.Close()
	}
}

func (m *rpcMux) HandleError(h ErrorHandler) {
	m.errh = h
}

func (m *rpcMux) handleErr(err error) bool {
	if !m.errh(err) {
		return false
	}

	if ne, ok := err.(net.Error); ok {
		return ne.Temporary()
	}

	return false
}

type muxListener struct {
	net.Listener
	connc chan net.Conn
}

func (l muxListener) Accept() (net.Conn, error) {
	c, ok := <-l.connc
	if !ok {
		return nil, ErrListenerClosed
	}
	return c, nil
}

// MuxConn wraps a net.Conn and provides transparent sniffing of connection data.
type MuxConn struct {
	net.Conn
	buf bufferedReader
}

func newMuxConn(c net.Conn) *MuxConn {
	return &MuxConn{
		Conn: c,
		buf:  bufferedReader{source: c},
	}
}

func (m *MuxConn) Read(p []byte) (int, error) {
	return m.buf.Read(p)
}

func (m *MuxConn) startSniffing() io.Reader {
	m.buf.reset(true)
	return &m.buf
}

func (m *MuxConn) doneSniffing() {
	m.buf.reset(false)
}

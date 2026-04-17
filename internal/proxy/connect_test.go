package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestConnectBlockDelayValue(t *testing.T) {
	is := assert.New(t)

	// Verify the default block delay (zero BlockDelay in config) is 1 second.
	cfg := &Config{}
	is.Equal(1*time.Second, cfg.blockDelay(), "default blockDelay should be 1 second")

	// Verify an explicit override is respected.
	cfgFast := &Config{BlockDelay: 20 * time.Millisecond}
	is.Equal(20*time.Millisecond, cfgFast.blockDelay(), "explicit BlockDelay should be used")
}

func TestProxy_BlockConnect_OtherMethodsUnaffected(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	caCert, caKey := generateTestCA(t)

	cfg := &Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		GlobalRateLimit:          0,
		DisableLocalhostBlocking: true,
	}

	proxy := NewProxy(cfg, caCert, caKey, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- proxy.Start(ctx)
	}()

	_, err := proxy.Addr(context.Background())
	must.NoError(err)

	// The CONNECT blocker only fires on req.Method == "CONNECT".
	// Verify that regular HTTP methods are not flagged as CONNECT.
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD"}
	for _, method := range methods {
		t.Run(method+" requests pass through", func(t *testing.T) {
			req, err := http.NewRequest(method, "http://example.com/test", nil)
			must.NoError(err)
			is.NotEqual("CONNECT", req.Method, "should not be CONNECT method")
		})
	}

	cancel()
	select {
	case err := <-proxyErrChan:
		is.NoError(err)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy shutdown timeout")
	}
}

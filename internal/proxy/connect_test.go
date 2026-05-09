package proxy

import (
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectAction(t *testing.T) {
	is := assert.New(t)

	caCert, caKey := generateTestCA(t)

	t.Run("without tlsBump returns goproxy default", func(t *testing.T) {
		p := &Proxy{}
		action := p.connectAction()
		is.Equal(goproxy.ConnectActionLiteral(goproxy.ConnectMitm), action.Action)
	})

	t.Run("with tlsBump returns mitmConnect", func(t *testing.T) {
		cfg := &Config{
			Listen:                   "localhost:0",
			ConnectionTimeout:        5 * time.Second,
			RequestTimeout:           10 * time.Second,
			DisableLocalhostBlocking: true,
		}
		p := NewProxy(cfg, caCert, caKey, nil, nil)
		action := p.connectAction()
		require.NotNil(t, p.tlsBump)
		is.Equal(p.tlsBump.mitmConnect, action)
	})
}

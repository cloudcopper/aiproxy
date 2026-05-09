package proxy

import (
	"github.com/elazarl/goproxy"
)

// connectAction returns the ConnectAction for all CONNECT requests.
// Uses per-instance TLS config when available, falls back to goproxy default.
func (p *Proxy) connectAction() *goproxy.ConnectAction {
	if p.tlsBump != nil {
		return p.tlsBump.mitmConnect
	}
	return goproxy.MitmConnect
}

//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

const (
	stsHost   = "auth.act.security"
	apiHost   = "api.us1.act.security"
	stsOrigin = "https://" + stsHost
	apiOrigin = "https://" + apiHost
)

var servedHosts = []string{stsHost, apiHost, "api.eu1.act.security"}

type pki struct {
	caFile string
	cert   tls.Certificate
}

func newPKI(dir, name string) (*pki, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "terraform-provider-act e2e " + name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: stsHost},
		DNSNames:     servedHosts,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caFile := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		return nil, err
	}
	return &pki{caFile: caFile, cert: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}, nil
}

type world struct {
	fake  *fakeapi.Fake
	proxy *connectProxy
}

func startWorld(t *testing.T, cfg fakeapi.Config) *world {
	t.Helper()
	fake, err := fakeapi.New(cfg, stsOrigin, apiOrigin)
	if err != nil {
		t.Fatal(err)
	}
	sts, api := fake.STSHandler(), fake.APIHandler()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch hostOnly(r.Host) {
		case stsHost:
			sts.ServeHTTP(w, r)
		case apiHost:
			api.ServeHTTP(w, r)
		default:
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{h.pki.cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &world{fake: fake, proxy: startProxy(t, srv.Listener.Addr().String())}
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

type connectProxy struct {
	target  string
	url     string
	mu      sync.Mutex
	refused []string
}

func startProxy(t *testing.T, target string) *connectProxy {
	t.Helper()
	p := &connectProxy{target: target}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

func (p *connectProxy) Refused() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.refused)
}

func (p *connectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if r.Method != http.MethodConnect || err != nil || port != "443" || !slices.Contains(servedHosts, host) {
		p.mu.Lock()
		p.refused = append(p.refused, r.Method+" "+r.Host)
		p.mu.Unlock()
		http.Error(w, "this proxy only reaches the fake Act hosts", http.StatusForbidden)
		return
	}
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(r.Context(), "tcp", p.target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		closeQuietly(upstream)
		http.Error(w, "the proxy cannot hijack this connection", http.StatusInternalServerError)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		closeQuietly(upstream)
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		closeQuietly(upstream)
		closeQuietly(conn)
		return
	}
	done := make(chan struct{})
	go func() {
		copyQuietly(upstream, buffered)
		closeQuietly(upstream)
		close(done)
	}()
	copyQuietly(conn, upstream)
	closeQuietly(conn)
	<-done
}

func copyQuietly(dst io.Writer, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("e2e proxy: %v", err)
	}
}

func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("e2e proxy: %v", err)
	}
}

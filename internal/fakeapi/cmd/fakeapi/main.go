package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

func main() {
	stsAddr := flag.String("addr", "127.0.0.1:8787", "loopback address for the fake STS")
	apiAddr := flag.String("api-addr", "127.0.0.1:8788", "loopback address for the fake public API")
	scriptPath := flag.String("script", "", "JSON script of canned responses, keyed by \"METHOD /path\"")
	flag.Parse()

	if err := run(*stsAddr, *apiAddr, *scriptPath); err != nil {
		log.Fatalf("fakeapi: %v", err)
	}
}

func run(stsAddr, apiAddr, scriptPath string) error {
	for _, addr := range []string{stsAddr, apiAddr} {
		if err := requireLoopback(addr); err != nil {
			return err
		}
	}
	cfg := fakeapi.DefaultConfig()
	if scriptPath != "" {
		script, err := fakeapi.LoadScript(scriptPath)
		if err != nil {
			return err
		}
		cfg.Script = script
	}
	fake, err := fakeapi.New(cfg, "http://"+stsAddr, "http://"+apiAddr)
	if err != nil {
		return err
	}

	servers := []*http.Server{
		{Addr: stsAddr, Handler: fake.STSHandler(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: apiAddr, Handler: fake.APIHandler(), ReadHeaderTimeout: 5 * time.Second},
	}
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	log.Printf("fake STS on http://%s, fake public API on http://%s", stsAddr, apiAddr)
	log.Printf("tenant %s, client %s, region %s", cfg.TenantID, cfg.ClientID, cfg.Region)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback address; the fake only listens on loopback", addr)
	}
	return nil
}

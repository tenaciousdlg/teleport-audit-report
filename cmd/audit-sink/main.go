// audit-sink is the receiving end of Teleport's Event Handler plugin. It
// speaks the same HTTP+mTLS contract the plugin normally uses to forward
// events to Fluentd/Logstash, but writes straight into Postgres instead.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tenaciousdlg/teleport-audit-report/internal/db"
	"github.com/tenaciousdlg/teleport-audit-report/internal/ingest"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("audit-sink: %v", err)
	}
}

func run() error {
	addr := envOr("LISTEN_ADDR", ":8443")
	dsn := mustEnv("DATABASE_URL")
	caPath := mustEnv("TLS_CA_PATH")
	certPath := mustEnv("TLS_CERT_PATH")
	keyPath := mustEnv("TLS_KEY_PATH")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	store := ingest.NewStore(pool)

	tlsConfig, err := serverTLSConfig(caPath, certPath, keyPath)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	// Routes match the Event Handler's configured `fluentd.url` /
	// `fluentd.sessionUrl` paths — both carry the same JSON event shape.
	mux.HandleFunc("/events.log", handleEvent(store))
	mux.HandleFunc("/session.log", handleEvent(store))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("audit-sink listening on %s", addr)
		errCh <- srv.ListenAndServeTLS(certPath, keyPath)
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
	return nil
}

// handleEvent accepts one JSON-encoded audit event per request. Teleport's
// Event Handler treats any non-200 response as a failure and retries with
// backoff, which duplicates events on the next attempt if the write actually
// succeeded — so this always returns 200 once the event is durably stored
// (or intentionally dropped as unparseable), never 201 or anything else.
func handleEvent(store *ingest.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		if err := store.Upsert(r.Context(), body); err != nil {
			log.Printf("upsert failed: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func serverTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, os.ErrInvalid
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var %s", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

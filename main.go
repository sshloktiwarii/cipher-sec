package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

type SentinelConfig struct {
	Port              string
	TargetURL         string
	TelemetryEndpoint string
}

type SentinelProxy struct {
	targetURL       *url.URL
	proxy           *httputil.ReverseProxy
	scannedRequests uint64
	blockedRequests uint64
	redactedSecrets uint64
	telemetryURL    string
	client          *http.Client
}

func NewSentinelProxy(cfg SentinelConfig) (*SentinelProxy, error) {
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid TARGET_URL: %w", err)
	}

	sp := &SentinelProxy{
		targetURL:    target,
		telemetryURL: cfg.TelemetryEndpoint,
		client:       &http.Client{Timeout: 2 * time.Second},
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Response inspection & redaction (zero leak to clients)
		if resp.Body != nil {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err == nil {
				_ = resp.Body.Close()
				sanitized, _, _ := InspectAndSanitize(bodyBytes)
				resp.Body = io.NopCloser(bytes.NewBuffer(sanitized))
				resp.ContentLength = int64(len(sanitized))
				resp.Header.Set("Content-Length", strconv.Itoa(len(sanitized)))
			}
		}
		return nil
	}

	sp.proxy = proxy
	return sp, nil
}

func (sp *SentinelProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&sp.scannedRequests, 1)

	// 1. Healthcheck
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"service":          "foundry-sentinel",
			"status":           "active",
			"scanned_requests": atomic.LoadUint64(&sp.scannedRequests),
			"blocked_threats":  atomic.LoadUint64(&sp.blockedRequests),
			"target_upstream":  sp.targetURL.String(),
			"timestamp":        time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// CORS Preflight
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 2. Request Payload Inspection
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to read body or body exceeds 5MB limit"}}`, http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()

		sanitized, blocked, reason := InspectAndSanitize(bodyBytes)
		if blocked {
			atomic.AddUint64(&sp.blockedRequests, 1)
			log.Printf("🚨 [SENTINEL REJECT] Blocked threat from %s: %s", r.RemoteAddr, reason)

			sp.emitThreatTelemetry("destructive_command_blocked", reason)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": "Blocked by Sentinel: Destructive command detected",
					"reason":  reason,
					"code":    403,
				},
			})
			return
		}

		if bytes.Contains(sanitized, []byte(RedactedPlaceholder)) {
			atomic.AddUint64(&sp.redactedSecrets, 1)
			log.Printf("🛡️ [SENTINEL REDACT] Redacted leaked secrets in request from %s", r.RemoteAddr)
			sp.emitThreatTelemetry("secrets_redacted", "API key or token stripped from payload")
		}

		// Rewire sanitized body into request
		r.Body = io.NopCloser(bytes.NewBuffer(sanitized))
		r.ContentLength = int64(len(sanitized))
		r.Header.Set("Content-Length", strconv.Itoa(len(sanitized)))
	}

	// Forward to target upstream
	w.Header().Set("X-Foundry-Sentinel", "INSPECTED")
	sp.proxy.ServeHTTP(w, r)
}

func (sp *SentinelProxy) emitThreatTelemetry(eventType, reason string) {
	if sp.telemetryURL == "" {
		return
	}
	go func() {
		payload := map[string]interface{}{
			"source":     "foundry-sentinel",
			"event_type": eventType,
			"metrics": map[string]float64{
				"threat_count": 1.0,
			},
			"metadata": map[string]string{
				"reason": reason,
				"action": "redact_or_block",
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		}
		data, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, sp.telemetryURL, bytes.NewBuffer(data))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := sp.client.Do(req)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}
	}()
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	port := flag.String("port", getEnv("PORT", "8079"), "Sentinel HTTP listen port")
	target := flag.String("target", getEnv("TARGET_URL", "http://localhost:8080"), "Target Foundry Router URL")
	telemetry := flag.String("telemetry", getEnv("TELEMETRY_ENDPOINT", "http://localhost:8082/ingest"), "Telemetry ingestion endpoint")
	flag.Parse()

	cfg := SentinelConfig{
		Port:              *port,
		TargetURL:         *target,
		TelemetryEndpoint: *telemetry,
	}

	proxy, err := NewSentinelProxy(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize Sentinel proxy: %v", err)
	}

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      proxy,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[INIT] Foundry Sentinel listening on :%s -> Forwarding to %s", cfg.Port, cfg.TargetURL)
		log.Printf("[INIT] Security: Destructive Command Intercept + Shannon Entropy Secret Redaction Active")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	<-stop
	log.Println("[SHUTDOWN] Exiting Foundry Sentinel...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

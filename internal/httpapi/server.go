// Package httpapi 暴露两个接口：POST /fingerprint 与 GET /health。
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"bannerprint/internal/fingerprint"
	"bannerprint/internal/ingest"
)

// Options 是服务端构造参数。
type Options struct {
	Engine   *fingerprint.Engine
	Logger   *slog.Logger
	Version  string
	MaxBody  int64
	MaxItems int
	Timeout  time.Duration
}

// Server 持有依赖，无全局状态。
type Server struct {
	opts  Options
	start time.Time
}

// New 构造 Server 并填充默认值。
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 64 << 20 // 64 MiB
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = 200000
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Server{opts: opts, start: time.Now()}
}

// Handler 组装路由与中间件。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fingerprint", s.handleFingerprint)
	mux.HandleFunc("GET /health", s.handleHealth)
	return s.middleware(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"reason": "rules not loaded",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"version":  s.opts.Version,
		"rules":    s.opts.Engine.Len(),
		"uptime_s": int(time.Since(s.start).Seconds()),
	})
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, s.opts.MaxBody)

	items, err := ingest.Batch(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error":  "request body too large",
				"detail": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid request body",
			"detail": err.Error(),
		})
		return
	}

	if len(items) > s.opts.MaxItems {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": "too many items in one batch",
		})
		return
	}

	results := make([]fingerprint.Result, len(items))
	for i, in := range items {
		results[i] = s.opts.Engine.Fingerprint(in)
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = newRequestID()
		}
		w.Header().Set("X-Request-ID", reqID)

		ctx, cancel := context.WithTimeout(r.Context(), s.opts.Timeout)
		defer cancel()

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					s.opts.Logger.Error("panic recovered",
						"error", rec, "path", r.URL.Path, "request_id", reqID)
					if !sw.wrote {
						writeJSON(sw, http.StatusInternalServerError, map[string]string{
							"error":      "internal error",
							"request_id": reqID,
						})
					}
				}
			}()
			next.ServeHTTP(sw, r.WithContext(ctx))
		}()

		s.opts.Logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(started).Milliseconds(),
			"remote", r.RemoteAddr,
			"request_id", reqID,
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func newRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(buf[:])
}

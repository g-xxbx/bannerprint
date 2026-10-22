package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bannerprint/internal/fingerprint"
	"bannerprint/internal/httpapi"
	"bannerprint/rules"
)

func newHandler(t *testing.T, maxItems int) http.Handler {
	t.Helper()

	loaded, err := fingerprint.LoadFS(rules.FS, rules.Dir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	engine, err := fingerprint.NewEngine(loaded)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	return httpapi.New(httpapi.Options{
		Engine:   engine,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		MaxItems: maxItems,
	}).Handler()
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler(t, 0).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %v", body["status"])
	}
	if body["rules"] == nil {
		t.Fatalf("rules field missing")
	}
}

func TestFingerprintBatch(t *testing.T) {
	payload := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},` +
		`{"ip":"1.2.3.23","port":12345,"banner":"QUIT"}]`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	newHandler(t, 0).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Protocol != "SSH" || results[0].Product != "OpenSSH" {
		t.Fatalf("unexpected first result: %+v", results[0])
	}
	if results[1].Protocol != "unknown" || results[1].Confidence != 0.1 {
		t.Fatalf("unexpected second result: %+v", results[1])
	}
}

func TestFingerprintEmptyBatch(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[]`))
	newHandler(t, 0).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("body = %q, want []", rec.Body.String())
	}
}

func TestFingerprintBadJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`{"ip":`))
	newHandler(t, 0).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestFingerprintTooManyItems(t *testing.T) {
	payload := `[{"ip":"a","port":1,"banner":"x"},{"ip":"b","port":2,"banner":"y"}]`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(payload))
	newHandler(t, 1).ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler(t, 0).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fingerprint", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

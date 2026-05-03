package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────
// Store tests
// ─────────────────────────────────────────────────────────────

func newTempStore(t *testing.T) *Store {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test_canaries.json")
	return NewStore(f)
}

func TestStoreAddAndGet(t *testing.T) {
	store := newTempStore(t)
	tok := &Token{
		ID:        newID(),
		Type:      TokenURL,
		Label:     "test token",
		CreatedAt: time.Now().UTC(),
	}
	store.Add(tok)

	got, ok := store.Get(tok.ID)
	if !ok {
		t.Fatal("token not found after Add")
	}
	if got.Label != "test token" {
		t.Errorf("unexpected label: %q", got.Label)
	}
}

func TestStoreRecordHit(t *testing.T) {
	store := newTempStore(t)
	tok := &Token{ID: newID(), Type: TokenURL, Label: "hit test", CreatedAt: time.Now()}
	store.Add(tok)

	h := Hit{Timestamp: time.Now(), IP: "1.2.3.4", UserAgent: "test-ua"}
	ok := store.RecordHit(tok.ID, h)
	if !ok {
		t.Fatal("RecordHit returned false for known token")
	}

	got, _ := store.Get(tok.ID)
	if len(got.Hits) != 1 {
		t.Errorf("expected 1 hit, got %d", len(got.Hits))
	}
	if got.Hits[0].IP != "1.2.3.4" {
		t.Errorf("unexpected IP: %s", got.Hits[0].IP)
	}
}

func TestStoreRecordHitUnknown(t *testing.T) {
	store := newTempStore(t)
	ok := store.RecordHit("nonexistent", Hit{})
	if ok {
		t.Error("RecordHit should return false for unknown token")
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.json")

	s1 := NewStore(path)
	tok := &Token{ID: newID(), Type: TokenURL, Label: "persist", CreatedAt: time.Now()}
	s1.Add(tok)

	// Re-open store from same file
	s2 := NewStore(path)
	_, ok := s2.Get(tok.ID)
	if !ok {
		t.Error("token not found after reload")
	}
}

// ─────────────────────────────────────────────────────────────
// HTTP server tests
// ─────────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	store := newTempStore(t)
	srv := &Server{store: store, webhookURL: "", baseURL: "http://localhost"}
	return srv, store
}

func TestServerHitKnownToken(t *testing.T) {
	srv, store := newTestServer(t)
	tok := &Token{ID: newID(), Type: TokenURL, Label: "srv test", CreatedAt: time.Now()}
	store.Add(tok)

	req := httptest.NewRequest(http.MethodGet, "/t/"+tok.ID, nil)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	got, _ := store.Get(tok.ID)
	if len(got.Hits) != 1 {
		t.Errorf("expected 1 hit recorded, got %d", len(got.Hits))
	}
	if got.Hits[0].IP != "10.0.0.1" {
		t.Errorf("unexpected IP: %s", got.Hits[0].IP)
	}
}

func TestServerHitUnknownToken(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/t/deadbeef", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestServerStatus(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("unexpected status body: %s", body)
	}
}

// ─────────────────────────────────────────────────────────────
// File token test
// ─────────────────────────────────────────────────────────────

func TestGenerateFileToken(t *testing.T) {
	store := newTempStore(t)
	dir := t.TempDir()
	tok := generateFile(store, "http://localhost:8080", "test file", dir)

	if tok == nil {
		t.Fatal("generateFile returned nil")
	}

	// Verify file was written
	files, _ := filepath.Glob(filepath.Join(dir, "canary_*.txt"))
	if len(files) == 0 {
		t.Error("no canary file written")
	}

	content, _ := os.ReadFile(files[0])
	if !strings.Contains(string(content), tok.ID) {
		t.Error("token ID not found in file content")
	}
}

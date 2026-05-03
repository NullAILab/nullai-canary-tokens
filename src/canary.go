// Package main — Canary Token Generator
//
// Generates canary tokens (honeytokens) that fire a webhook callback when
// accessed. Supports three token types:
//
//  1. URL token   — a unique tracking URL that fires on GET request
//  2. DNS token   — a subdomain that fires when DNS is queried (simulation)
//  3. File token  — a text file with a unique ID embedded (for file-drop honeytraps)
//
// The built-in HTTP server handles incoming token hits and logs them with
// IP, User-Agent, timestamp, and token ID.
//
// Usage:
//
//	./canary server --port 8080 --webhook https://hooks.slack.com/...
//	./canary generate url --label "HR Shared Drive link"
//	./canary generate file --label "payroll spreadsheet"
//	./canary list
//	./canary hits
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────
// Token types
// ─────────────────────────────────────────────────────────────

type TokenType string

const (
	TokenURL  TokenType = "url"
	TokenDNS  TokenType = "dns"
	TokenFile TokenType = "file"
)

// Token represents a single canary token.
type Token struct {
	ID        string    `json:"id"`
	Type      TokenType `json:"type"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	Hits      []Hit     `json:"hits"`
}

// Hit records one access event.
type Hit struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Extra     string    `json:"extra,omitempty"`
}

// ─────────────────────────────────────────────────────────────
// Token store
// ─────────────────────────────────────────────────────────────

type Store struct {
	mu     sync.RWMutex
	tokens map[string]*Token
	path   string
}

func NewStore(path string) *Store {
	s := &Store{tokens: make(map[string]*Token), path: path}
	_ = s.load()
	return s
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) Add(t *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.ID] = t
	_ = s.save()
}

func (s *Store) Get(id string) (*Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	return t, ok
}

func (s *Store) RecordHit(id string, h Hit) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return false
	}
	t.Hits = append(t.Hits, h)
	_ = s.save()
	return true
}

func (s *Store) All() []*Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.tokens, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil // file doesn't exist yet
	}
	return json.Unmarshal(data, &s.tokens)
}

// ─────────────────────────────────────────────────────────────
// HTTP server
// ─────────────────────────────────────────────────────────────

type Server struct {
	store      *Store
	webhookURL string
	baseURL    string
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// GET /t/<id>  — token hit
	if strings.HasPrefix(r.URL.Path, "/t/") {
		id := strings.TrimPrefix(r.URL.Path, "/t/")
		id = strings.Trim(id, "/")
		srv.handleHit(w, r, id)
		return
	}
	// GET /status  — health check
	if r.URL.Path == "/status" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","tokens":%d}`, len(srv.store.All()))
		return
	}
	http.NotFound(w, r)
}

func (srv *Server) handleHit(w http.ResponseWriter, r *http.Request, id string) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	h := Hit{
		Timestamp: time.Now().UTC(),
		IP:        ip,
		UserAgent: r.Header.Get("User-Agent"),
		Extra:     r.URL.RawQuery,
	}

	found := srv.store.RecordHit(id, h)

	logLine := fmt.Sprintf("[HIT] %s  token=%s  ip=%s  ua=%s",
		h.Timestamp.Format(time.RFC3339), id, ip, h.UserAgent)

	if found {
		fmt.Println(logLine)
		if t, ok := srv.store.Get(id); ok {
			fmt.Printf("      label=%q\n", t.Label)
		}
		go srv.sendWebhook(id, h)
		// Return a 1×1 transparent GIF so image-type tokens don't error
		w.Header().Set("Content-Type", "image/gif")
		_, _ = w.Write([]byte("\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00" +
			"\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00" +
			"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"))
	} else {
		fmt.Println(logLine + "  [unknown token]")
		http.NotFound(w, r)
	}
}

func (srv *Server) sendWebhook(id string, h Hit) {
	if srv.webhookURL == "" {
		return
	}
	t, _ := srv.store.Get(id)
	label := ""
	if t != nil {
		label = t.Label
	}
	body := fmt.Sprintf(
		`{"text":"🪤 *Canary triggered!*\n• Token: %s\n• Label: %s\n• IP: %s\n• Time: %s\n• UA: %s"}`,
		id, label, h.IP, h.Timestamp.Format(time.RFC3339), h.UserAgent,
	)
	resp, err := http.Post(srv.webhookURL, "application/json",
		strings.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "[webhook error]", err)
		return
	}
	resp.Body.Close()
}

// ─────────────────────────────────────────────────────────────
// Token generation helpers
// ─────────────────────────────────────────────────────────────

func generateURL(store *Store, baseURL, label string) *Token {
	t := &Token{
		ID:        newID(),
		Type:      TokenURL,
		Label:     label,
		CreatedAt: time.Now().UTC(),
	}
	store.Add(t)
	fmt.Printf("[+] URL token created\n    ID    : %s\n    URL   : %s/t/%s\n    Label : %s\n\n",
		t.ID, baseURL, t.ID, label)
	return t
}

func generateFile(store *Store, baseURL, label, outDir string) *Token {
	t := &Token{
		ID:        newID(),
		Type:      TokenFile,
		Label:     label,
		CreatedAt: time.Now().UTC(),
	}
	store.Add(t)

	content := fmt.Sprintf(
		"[NullAI Canary Token]\nID: %s\nLabel: %s\nCreated: %s\n\nThis file is a honeytoken. "+
			"If you are reading this file unexpectedly, please verify you are authorised to access it.\n"+
			"Tracking URL (do not access): %s/t/%s\n",
		t.ID, label, t.CreatedAt.Format(time.RFC3339), baseURL, t.ID,
	)

	filename := filepath.Join(outDir, fmt.Sprintf("canary_%s.txt", t.ID[:8]))
	_ = os.WriteFile(filename, []byte(content), 0644)

	fmt.Printf("[+] File token created\n    ID    : %s\n    File  : %s\n    Label : %s\n\n",
		t.ID, filename, label)
	return t
}

// ─────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────

func main() {
	const storeFile = "canaries.json"

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: canary <server|generate|list|hits> [options]")
		os.Exit(1)
	}

	store := NewStore(storeFile)

	switch os.Args[1] {

	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		port    := fs.Int("port", 8080, "Listen port")
		webhook := fs.String("webhook", "", "Webhook URL for hit notifications")
		base    := fs.String("base-url", "", "Public base URL (default: http://localhost:<port>)")
		_ = fs.Parse(os.Args[2:])

		baseURL := *base
		if baseURL == "" {
			baseURL = fmt.Sprintf("http://localhost:%d", *port)
		}

		srv := &Server{store: store, webhookURL: *webhook, baseURL: baseURL}
		addr := fmt.Sprintf(":%d", *port)
		fmt.Printf("[*] Canary server listening on %s\n    Base URL : %s\n", addr, baseURL)
		if err := http.ListenAndServe(addr, srv); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "generate":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: canary generate <url|file> [options]")
			os.Exit(1)
		}
		fs := flag.NewFlagSet("generate", flag.ExitOnError)
		label   := fs.String("label", "unlabelled", "Human-readable description")
		baseURL := fs.String("base-url", "http://localhost:8080", "Server base URL")
		outDir  := fs.String("out-dir", ".", "Output directory for file tokens")
		_ = fs.Parse(os.Args[3:])

		switch os.Args[2] {
		case "url":
			generateURL(store, *baseURL, *label)
		case "file":
			generateFile(store, *baseURL, *label, *outDir)
		default:
			fmt.Fprintln(os.Stderr, "Unknown token type:", os.Args[2])
			os.Exit(1)
		}

	case "list":
		tokens := store.All()
		if len(tokens) == 0 {
			fmt.Println("No tokens.")
			return
		}
		fmt.Printf("%-26s %-8s %-30s %s\n", "ID", "Type", "Label", "Hits")
		fmt.Println(strings.Repeat("─", 80))
		for _, t := range tokens {
			fmt.Printf("%-26s %-8s %-30s %d\n",
				t.ID, t.Type, t.Label, len(t.Hits))
		}

	case "hits":
		tokens := store.All()
		total := 0
		for _, t := range tokens {
			total += len(t.Hits)
		}
		fmt.Printf("Total hits: %d across %d tokens\n\n", total, len(tokens))
		for _, t := range tokens {
			if len(t.Hits) == 0 {
				continue
			}
			fmt.Printf("Token %s  [%s]  %q\n", t.ID[:8], t.Type, t.Label)
			for _, h := range t.Hits {
				fmt.Printf("  %s  ip=%-18s  ua=%s\n",
					h.Timestamp.Format("2006-01-02 15:04:05"), h.IP, h.UserAgent)
			}
			fmt.Println()
		}

	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", os.Args[1])
		os.Exit(1)
	}
}

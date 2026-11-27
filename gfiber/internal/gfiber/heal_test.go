package gfiber

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// auth0Stub replays the walk measured on signin.gfiber.com (2026-11-27):
// login route -> authorize -> identifier -> password -> challenge ->
// callback chain that mints __session__0 on the app host.
type auth0Stub struct {
	mu        sync.Mutex
	codes     string          // what the verify POST must receive
	stateHits map[string]bool // observed state params
	resendOK  bool            // challenge accepted action=resend
}

func auth0Fixture(t *testing.T, s *auth0Stub) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	const state = "STUBSTATE"
	html := func(code string) string {
		return fmt.Sprintf(`<html><form method="POST"><input type="hidden" name="state" value="%s"/>`, code) +
			`<input name="code"/><button type="submit" name="action" value="default">Go</button></form></html>`
	}
	mux.HandleFunc("/account/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/authorize?client_id=x", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/u/login/identifier?state="+state, http.StatusFound)
	})
	mux.HandleFunc("/u/login/identifier", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil || r.FormValue("username") == "" {
				w.WriteHeader(400)
				return
			}
			s.mu.Lock()
			s.stateHits["identifier"] = true
			s.mu.Unlock()
			http.Redirect(w, r, "/u/login/password?state="+state, http.StatusFound)
			return
		}
		w.Write([]byte(html(state)))
	})
	mux.HandleFunc("/u/login/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.FormValue("connection") != "email" {
				w.WriteHeader(422)
				return
			}
			http.Redirect(w, r, "/u/login/passwordless-email-challenge?state="+state, http.StatusFound)
			return
		}
		w.Write([]byte(html(state)))
	})
	mux.HandleFunc("/u/login/passwordless-email-challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.FormValue("action") == "resend" {
				s.mu.Lock()
				s.resendOK = true
				s.mu.Unlock()
				http.Redirect(w, r, "/u/login/passwordless-email-challenge?state="+state, http.StatusFound)
				return
			}
			if r.FormValue("code") != s.codes {
				w.WriteHeader(401)
				return
			}
			http.Redirect(w, r, "/account/auth/callback?state="+state, http.StatusFound)
			return
		}
		w.Write([]byte(html(state)))
	})
	mux.HandleFunc("/account/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__session__0", Value: "S0VALUE", Path: "/account"})
		http.SetCookie(w, &http.Cookie{Name: "__session__1", Value: "S1VALUE", Path: "/account"})
		http.Redirect(w, r, "/account/", http.StatusFound)
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>SPA</html>"))
	})
	return httptest.NewServer(mux)
}

type stubFetcher struct {
	codes []string // returned one per call, last repeats
	calls int
	errOn int // inject an error on call N (1-based), 0 = never
}

func (f *stubFetcher) LatestCode(context.Context, time.Time) (string, error) {
	f.calls++
	if f.errOn == f.calls {
		return "", fmt.Errorf("stub gmail hiccup")
	}
	i := f.calls - 1
	if i >= len(f.codes) {
		i = len(f.codes) - 1
	}
	if i < 0 {
		return "", nil
	}
	return f.codes[i], nil
}

func TestAuth0MintWalk(t *testing.T) {
	stub := &auth0Stub{codes: "654321", stateHits: map[string]bool{}}
	srv := auth0Fixture(t, stub)
	defer srv.Close()
	gmail := &stubFetcher{codes: []string{"", "654321"}}
	a := NewAuth0(Auth0Config{
		LoginURL:   srv.URL + "/account/auth/login?returnTo=%2Faccount%2F",
		Email:      "bob@example.com",
		Fetcher:    gmail,
		PollEvery:  10 * time.Millisecond,
		PollMax:    2 * time.Second,
		ResendAt:   time.Second,
		HTTPClient: &http.Client{},
	}, nil)
	cookies, err := a.Mint(context.Background())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if cookies["__session__0"] != "S0VALUE" || cookies["__session__1"] != "S1VALUE" {
		t.Fatalf("session cookies not harvested: %+v", cookies)
	}
	if !stub.stateHits["identifier"] {
		t.Fatal("identifier POST never happened")
	}
	if gmail.calls < 2 {
		t.Fatalf("fetcher should be polled until the code lands, calls=%d", gmail.calls)
	}
}

func TestAuth0MintWrongCode(t *testing.T) {
	stub := &auth0Stub{codes: "111111", stateHits: map[string]bool{}} // the walk will submit 222222
	srv := auth0Fixture(t, stub)
	defer srv.Close()
	a := NewAuth0(Auth0Config{
		LoginURL:   srv.URL + "/account/auth/login?returnTo=%2Faccount%2F",
		Email:      "bob@example.com",
		Fetcher:    &stubFetcher{codes: []string{"222222"}},
		PollEvery:  5 * time.Millisecond,
		PollMax:    time.Second,
		ResendAt:   time.Second,
		HTTPClient: &http.Client{},
	}, nil)
	if _, err := a.Mint(context.Background()); err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("wrong code must fail at verify, got %v", err)
	}
}

// fakePortal is a Poller double: Heal only uses the RPC counters.
func newTestPoller(t *testing.T) *Poller {
	t.Helper()
	srv := fixtureServer(t)
	t.Cleanup(srv.Close)
	return New(Config{BaseURL: srv.URL})
}

func TestHealGuardsAndStandDown(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "cookies")
	os.WriteFile(jar, []byte("__session__0=old; __session__1=old"), 0o600)
	ledger := filepath.Join(dir, "ledger.csv")

	now := time.Date(2026, 11, 27, 22, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	mints := 0
	failFor := 0 // first N mints fail
	heal := &Heal{
		Mint: func(context.Context) (map[string]string, error) {
			mu.Lock()
			mints++
			n := mints
			mu.Unlock()
			if n <= failFor {
				return nil, fmt.Errorf("stub mint failure")
			}
			return map[string]string{"__session__0": "new0", "__session__1": "new1"}, nil
		},
		CookieFile:  jar,
		LedgerFile:  ledger,
		MinInterval: 30 * time.Minute,
		Log:         discardLogger(),
		Now:         func() time.Time { return now },
	}
	p := newTestPoller(t)
	p.Poll(context.Background()) // grow the rpc counter
	dead := &SessionError{Path: "x", Code: 401}

	// Two failures stand the healer down…
	failFor = 2
	if heal.MaybeMint(context.Background(), p, dead) {
		t.Fatal("failed mint must report false")
	}
	now = now.Add(31 * time.Minute) // out of the guard window
	if heal.MaybeMint(context.Background(), p, dead) {
		t.Fatal("second failure must report false")
	}
	if !heal.stopped {
		t.Fatal("two consecutive failures must stand autoheal down")
	}
	if heal.MaybeMint(context.Background(), p, dead) {
		t.Fatal("standing-down healer must stop minting")
	}
	if mints != 2 {
		t.Fatalf("mints after stand-down: %d", mints)
	}
}

func TestHealHappyPath(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "cookies")
	os.WriteFile(jar, []byte("__session__0=old; auth0=keepme"), 0o600)
	ledger := filepath.Join(dir, "ledger.csv")

	minted := time.Date(2026, 11, 26, 22, 0, 0, 0, time.UTC) // 24 h lifetime
	now := minted.Add(24 * time.Hour)
	heal := &Heal{
		Mint: func(context.Context) (map[string]string, error) {
			return map[string]string{"__session__0": "fresh"}, nil
		},
		CookieFile:  jar,
		LedgerFile:  ledger,
		MinInterval: 30 * time.Minute,
		Log:         discardLogger(),
		Now:         func() time.Time { return now },
	}
	// Pre-arm the sidecar as a previous heal would have.
	heal.writeMinted(minted)
	p := newTestPoller(t)
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("fixture poll: %v", err)
	}
	rpcsWant := p.RPCs()
	if rpcsWant == 0 {
		t.Fatal("fixture poll should count RPCs")
	}
	if !heal.MaybeMint(context.Background(), p, &SessionError{Code: 403}) {
		t.Fatal("happy heal must report true")
	}
	b, _ := os.ReadFile(jar)
	s := string(b)
	if !strings.Contains(s, "__session__0=fresh") || strings.Contains(s, "=old") {
		t.Fatalf("jar not swapped: %q", s)
	}
	if !strings.Contains(s, "auth0=keepme") {
		t.Fatalf("non-session cookies must survive: %q", s)
	}
	if p.RPCs() != 0 {
		t.Fatal("rpc counter must reset for the new session")
	}
	lb, _ := os.ReadFile(ledger)
	row := string(lb)
	if !strings.Contains(row, "autoheal") || !strings.Contains(row, fmt.Sprintf("rpcs=%d", rpcsWant)) {
		t.Fatalf("ledger row wrong: %q", row)
	}
	if !strings.Contains(row, "24h00m") {
		t.Fatalf("ledger age math wrong (want 24h00m): %q", row)
	}
	// Guard: a death right after a heal waits for the window.
	if heal.MaybeMint(context.Background(), p, &SessionError{Code: 401}) {
		t.Fatal("guard window must skip immediate re-mints")
	}
}

func TestGmailLatestCode(t *testing.T) {
	var tokenCalls, msgCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	mux.HandleFunc("/gmail/v1/users/me/messages", func(w http.ResponseWriter, r *http.Request) {
		msgCalls++
		q := r.URL.Query().Get("q")
		if !strings.Contains(q, "newer_than:") {
			t.Errorf("query lacks newer_than: %q", q)
		}
		w.Write([]byte(`{"messages":[{"id":"m1"}]}`))
	})
	mux.HandleFunc("/gmail/v1/users/me/messages/m1", func(w http.ResponseWriter, r *http.Request) {
		body := base64.URLEncoding.EncodeToString([]byte("Enter your code: 508221 to sign in"))
		w.Write([]byte(fmt.Sprintf(
			`{"internalDate":"%d","snippet":"whatever","payload":{"mimeType":"text/plain","body":{"data":"%s"}}}`,
			time.Now().UnixMilli(), body)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := NewGmail(GoogleCreds{ClientID: "c", ClientSecret: "s", RefreshToken: "r"})
	g.TokenURL = srv.URL + "/token"
	g.APIBase = srv.URL
	code, err := g.LatestCode(context.Background(), time.Now().Add(-2*time.Minute))
	if err != nil {
		t.Fatalf("LatestCode: %v", err)
	}
	if code != "508221" {
		t.Fatalf("code from body: %q", code)
	}
	// Second call must reuse the cached token.
	if _, err := g.LatestCode(context.Background(), time.Now()); err != nil {
		t.Fatalf("second LatestCode: %v", err)
	}
	if tokenCalls != 1 {
		t.Fatalf("token must be cached, got %d exchanges", tokenCalls)
	}
}

func TestGmailIgnoresOldMail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	mux.HandleFunc("/gmail/v1/users/me/messages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"messages":[{"id":"m1"}]}`))
	})
	mux.HandleFunc("/gmail/v1/users/me/messages/m1", func(w http.ResponseWriter, r *http.Request) {
		old := time.Now().Add(-1 * time.Hour).UnixMilli()
		w.Write([]byte(fmt.Sprintf(`{"internalDate":"%d","snippet":"code 111222 here"}`, old)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := NewGmail(GoogleCreds{ClientID: "c", ClientSecret: "s", RefreshToken: "r"})
	g.TokenURL = srv.URL + "/token"
	g.APIBase = srv.URL
	code, err := g.LatestCode(context.Background(), time.Now().Add(-5*time.Minute))
	if err != nil || code != "" {
		t.Fatalf("mail older than notBefore must not replay: %q %v", code, err)
	}
}

func TestLoadGoogleCredsShapes(t *testing.T) {
	dir := t.TempDir()
	flat := filepath.Join(dir, "flat.json")
	os.WriteFile(flat, []byte(`{"client_id":"a","client_secret":"b","refresh_token":"c"}`), 0o600)
	c, err := LoadGoogleCreds(flat)
	if err != nil || c.ClientID != "a" || c.RefreshToken != "c" {
		t.Fatalf("flat: %+v %v", c, err)
	}
	wrapped := filepath.Join(dir, "wrapped.json")
	os.WriteFile(wrapped, []byte(`{"installed":{"client_id":"x","client_secret":"y"},"refresh_token":"z"}`), 0o600)
	c, err = LoadGoogleCreds(wrapped)
	if err != nil || c.ClientID != "x" || c.ClientSecret != "y" || c.RefreshToken != "z" {
		t.Fatalf("wrapped: %+v %v", c, err)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"client_id":"a"}`), 0o600)
	if _, err := LoadGoogleCreds(bad); err == nil {
		t.Fatal("missing fields must error")
	}
}

func TestFmtAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2*time.Hour + 35*time.Minute:  "2h35m",
		23*time.Hour + 31*time.Minute: "23h31m",
		45 * time.Second:              "0h00m",
	} {
		if got := fmtAge(d); got != want {
			t.Errorf("fmtAge(%v)=%s want %s", d, got, want)
		}
	}
}

// url must stay imported for auth0Stub signature compatibility checks.
var _ = url.Values{}

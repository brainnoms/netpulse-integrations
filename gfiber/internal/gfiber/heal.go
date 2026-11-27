// Autoheal glue: turn "session died" into "session re-minted" without a
// human, and keep the watchdog's lifetime ledger growing for free.
//
// Doctrine (card t_cfc1bb81): detection drives action — the poll loop calls
// MaybeMint on the FIRST 401/403 of a death episode. Auth0 rate limits make
// aggressive re-minting worse than a slow heal, hence the guard window; and
// when the walk itself keeps failing the pusher stands down and lets the
// watchdog's HA ping do the shouting.
package gfiber

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Heal owns the headless re-mint policy around a session minter.
type Heal struct {
	// Mint performs the headless login and returns fresh __session__
	// cookies (Auth0.Mint in production).
	Mint func(ctx context.Context) (map[string]string, error)
	// CookieFile is the pusher's raw-Cookie jar; the fresh pair is merged
	// into it (temp+rename, 0600) so every poll picks it up.
	CookieFile string
	// MintedFile is a sidecar holding the mint timestamp (RFC3339); it
	// makes "session age at death" computable across restarts. Empty
	// defaults to CookieFile + ".minted".
	MintedFile string
	// LedgerFile optionally receives watchdog-compatible CSV rows
	// (session_start,death_time,age_hours,provenance,note) appended per
	// heal, so the TTL-distribution table keeps growing.
	LedgerFile string
	// MinInterval is the Auth0 rate guard: no second walk starts within
	// this window of the last attempt. Zero defaults to 30 m.
	MinInterval time.Duration
	// FailStop is the consecutive-failure stand-down count (0 = 2).
	FailStop int
	Log      *slog.Logger
	// Now is overridable for tests.
	Now func() time.Time

	mu          sync.Mutex
	lastAttempt time.Time
	failures    int
	stopped     bool
}

// MaybeMint attempts one headless re-mint for the death reported by cause
// and reports whether the caller should retry the poll immediately. It
// enforces the guard window, the failure stand-down, the jar swap, the
// sidecar and the ledger row. Deaths inside the guard window are logged and
// left to the watchdog alarm.
func (h *Heal) MaybeMint(ctx context.Context, p *Poller, cause error) bool {
	now := h.now()
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		h.logger().Warn("gfiber: autoheal is standing down after repeated failures — watchdog owns the alarm", "cause", cause)
		return false
	}
	if h.MinInterval > 0 && !h.lastAttempt.IsZero() && now.Sub(h.lastAttempt) < h.MinInterval {
		h.mu.Unlock()
		h.logger().Warn("gfiber: session death inside the re-mint guard window — leaving it to the next episode",
			"since_last_attempt", now.Sub(h.lastAttempt).Truncate(time.Second), "cause", cause)
		return false
	}
	age := h.sessionAgeLocked(now)
	h.lastAttempt = now
	h.mu.Unlock()

	rpcs := p.RPCs()
	cookies, err := h.Mint(ctx)
	h.mu.Lock()
	if err != nil {
		h.failures++
		stopped := h.failures >= h.failStop()
		h.stopped = stopped
		h.mu.Unlock()
		h.logger().Error("gfiber: headless re-mint failed", "err", err, "consecutive_failures", h.failures, "standing_down", stopped)
		return false
	}
	h.failures = 0
	h.mu.Unlock()

	h.swapJar(cookies, now)
	rpcs = p.ResetRPCs()

	ageStr := "unknown"
	if !age.IsZero() {
		ageStr = fmtAge(now.Sub(age))
	}
	h.logger().Info("gfiber: session re-minted headlessly", "age", ageStr, "rpcs", rpcs, "cookies", len(cookies))
	h.ledgerRow(age, now, rpcs)
	return true
}

// swapJar merges the fresh session cookies into the raw-Cookie jar file.
// Only __session__* names are touched; anything else the operator dropped
// into the file survives the swap.
func (h *Heal) swapJar(cookies map[string]string, at time.Time) {
	var order []string
	vals := map[string]string{}
	if b, err := os.ReadFile(h.CookieFile); err == nil {
		order, vals = parseCookieState(string(b))
	}
	for name, value := range cookies {
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = value
	}
	tmp := h.CookieFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(serializeCookies(order, vals)), 0o600); err != nil {
		h.logger().Error("gfiber: could not persist re-minted cookies", "err", err)
		return
	}
	if err := os.Rename(tmp, h.CookieFile); err != nil {
		h.logger().Error("gfiber: could not rename re-minted cookie jar", "err", err)
		return
	}
	h.writeMinted(at)
}

// writeMinted records the mint timestamp for age math at the next death.
func (h *Heal) writeMinted(at time.Time) {
	path := h.mintedPath()
	if path == "" {
		return
	}
	if err := os.WriteFile(path, []byte(at.UTC().Format(time.RFC3339)), 0o600); err != nil {
		h.logger().Warn("gfiber: minted-time sidecar write failed", "err", err)
	}
}

// sessionAgeLocked returns the mint timestamp of the current session (zero
// when unknown — the session predates autoheal bookkeeping).
func (h *Heal) sessionAgeLocked(now time.Time) time.Time {
	path := h.mintedPath()
	if path == "" {
		return time.Time{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, string(b))
	if err != nil {
		return time.Time{}
	}
	return t
}

// ledgerRow appends one watchdog-compatible row to the bootstrap ledger so
// every heal feeds the session-lifetime distribution. The watchdog records
// deaths; autoheal records cures — provenance tells them apart.
func (h *Heal) ledgerRow(minted, healed time.Time, rpcs uint64) {
	if h.LedgerFile == "" {
		return
	}
	start, age := "", "unknown"
	if !minted.IsZero() {
		start = minted.UTC().Format(time.RFC3339)
		age = fmtAge(healed.Sub(minted))
	}
	// Mirror the watchdog's CRLF line endings (python csv default) so the
	// file stays uniform for its readers.
	row := fmt.Sprintf("%s,%s,%s,autoheal,\"headless re-mint, rpcs=%d\"\r\n",
		start, healed.UTC().Format(time.RFC3339), age, rpcs)
	f, err := os.OpenFile(h.LedgerFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		h.logger().Warn("gfiber: ledger append failed", "err", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(row); err != nil {
		h.logger().Warn("gfiber: ledger write failed", "err", err)
	}
}

func (h *Heal) mintedPath() string {
	if h.MintedFile != "" {
		return h.MintedFile
	}
	if h.CookieFile != "" {
		return h.CookieFile + ".minted"
	}
	return ""
}

func (h *Heal) failStop() int {
	if h.FailStop > 0 {
		return h.FailStop
	}
	return 2
}

func (h *Heal) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Heal) logger() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// fmtAge renders a lifetime the way the watchdog ledger does ("23h31m").
func fmtAge(d time.Duration) string {
	m := int(d.Minutes())
	if m < 0 {
		m = 0
	}
	return fmt.Sprintf("%dh%02dm", m/60, m%60)
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gnacho/netpulse-integrations/gfiber"
	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse/agent/probe"
)

var Version = "0.3.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("gfiber-pusher", Version)
	if err != nil {
		return err
	}
	cookieFile, err := pusher.RequiredEnv("GFIBER_COOKIE_FILE")
	if err != nil {
		return err
	}
	poller := gfiber.New(gfiber.Config{
		BaseURL:         os.Getenv("GFIBER_BASE_URL"),
		CookieFile:      cookieFile,
		RouterMAC:       os.Getenv("GFIBER_ROUTER_MAC"),
		ExtenderClients: parseClients(os.Getenv("GFIBER_EXTENDER_CLIENTS")),
		SessionPingURL:  envOr("GFIBER_SESSION_PING_URL", "https://gfiber.com/account"),
	})

	// Autoheal: a session death (401/403) triggers a headless Auth0 OTP
	// re-mint with the code read straight from Gmail — no human relay.
	// Unconfigured (no account e-mail or no Google credentials) is a
	// supported state: the pusher keeps the honest-401 + watchdog model.
	healer, err := newHealer(cookieFile)
	if err != nil {
		slog.Warn("gfiber-pusher: autoheal disabled", "reason", err)
		healer = nil
	}

	// One portal poll feeds N fleet rows: the gateway (cfg.Slug/cfg.Token)
	// plus one row per mesh extender, each with its own agent token from
	// GFIBER_TOKEN_<SLUG uppercased, dashes to underscores>. Rows without a
	// token are skipped with a warning — minting is an operator act.
	interval := cfg.Interval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	missed := map[string]bool{}
	for {
		data, err := poller.Poll(ctx)
		var se *gfiber.SessionError
		if err != nil && errors.As(err, &se) && healer != nil {
			if healer.MaybeMint(ctx, poller, se) {
				data, err = poller.Poll(ctx) // healed: retry the cycle now
			}
		}
		if err != nil {
			slog.Error("gfiber-pusher: collection failed", "err", err)
		} else {
			gw := &probe.Payload{Data: *data}
			normalize(cfg, gw)
			if err := pusher.Push(ctx, cfg, gw); err != nil {
				slog.Error("gfiber-pusher: gateway push failed", "err", err)
			} else {
				slog.Info("gfiber-pusher: pushed", "slug", cfg.Slug)
			}
			for _, u := range poller.Units() {
				envKey := "GFIBER_TOKEN_" + strings.ToUpper(strings.ReplaceAll(u.Slug, "-", "_"))
				token := strings.TrimSpace(os.Getenv(envKey))
				if token == "" {
					if !missed[u.Slug] {
						slog.Warn("gfiber-pusher: no agent token for extender row", "slug", u.Slug, "env", envKey)
						missed[u.Slug] = true
					}
					continue
				}
				pl := &probe.Payload{Router: u.Slug, Ts: time.Now().Unix(), Version: cfg.Version, Kind: "external", Interval: int(interval.Seconds()), Data: u.Payload}
				if err := cfg.PushClient.Send(ctx, token, *pl); err != nil {
					slog.Error("gfiber-pusher: extender push failed", "slug", u.Slug, "err", err)
				} else {
					slog.Info("gfiber-pusher: pushed", "slug", u.Slug)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// envOr reads an env var with a default. "none" disables a defaulted
// setting (there is no way to distinguish unset from empty via the env).
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if v == "none" {
			return ""
		}
		return v
	}
	return def
}

// normalize fills the shared envelope fields exactly like pusher.Run does.
func normalize(cfg pusher.Config, pl *probe.Payload) {
	pl.Router = cfg.Slug
	pl.Ts = time.Now().Unix()
	pl.Version = cfg.Version
	pl.Kind = "external"
	pl.Interval = int(cfg.Interval.Seconds())
}

// parseClients reads GFIBER_EXTENDER_CLIENTS, the operator's physical-wiring
// map: "gfiber-kitchen=24:4B:FE:..,00:17:88:..;gfiber-upstairs=BC:89:C1:..".
// Semicolons split units, commas split MACs. Slugs must match the rows the
// portal nicknames mint (gfiber-<nickname>); MACs normalize to uppercase.
func parseClients(s string) map[string][]string {
	out := map[string][]string{}
	for _, grp := range strings.Split(s, ";") {
		slug, macs, ok := strings.Cut(grp, "=")
		slug = strings.ToLower(strings.TrimSpace(slug))
		if !ok || slug == "" {
			continue
		}
		for _, m := range strings.Split(macs, ",") {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
				out[slug] = append(out[slug], m)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// newHealer assembles the autoheal pipeline from the environment. It
// returns a descriptive error (not a half-wired healer) when the feature
// is not configured:
//
//	GFIBER_ACCOUNT_EMAIL        the portal account (enables autoheal)
//	GFIBER_GOOGLE_FILE          OAuth JSON + refresh token (~/.secrets/…)
//	GFIBER_GMAIL_QUERY          Gmail search override for the code e-mail
//	GFIBER_LOGIN_URL            login entry that mints a fresh transaction
//	GFIBER_AUTOHEAL_LEDGER      CSV to append heal rows to (watchdog ledger)
//	GFIBER_REMINT_MIN_INTERVAL  Auth0 rate guard, default 30m
func newHealer(cookieFile string) (*gfiber.Heal, error) {
	email := strings.TrimSpace(os.Getenv("GFIBER_ACCOUNT_EMAIL"))
	if email == "" {
		return nil, errors.New("GFIBER_ACCOUNT_EMAIL not set")
	}
	googleFile := strings.TrimSpace(os.Getenv("GFIBER_GOOGLE_FILE"))
	if googleFile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			googleFile = filepath.Join(home, ".secrets", "netpulse_gfiber_google.json")
		}
	}
	creds, err := gfiber.LoadGoogleCreds(googleFile)
	if err != nil {
		return nil, err
	}
	gmail := gfiber.NewGmail(creds)
	if q := strings.TrimSpace(os.Getenv("GFIBER_GMAIL_QUERY")); q != "" {
		gmail.Query = q
	}
	minInterval, err := time.ParseDuration(envOr("GFIBER_REMINT_MIN_INTERVAL", "30m"))
	if err != nil {
		return nil, fmt.Errorf("invalid GFIBER_REMINT_MIN_INTERVAL: %w", err)
	}
	auth0 := gfiber.NewAuth0(gfiber.Auth0Config{
		LoginURL: envOr("GFIBER_LOGIN_URL", "https://gfiber.com/account/auth/login?returnTo=%2Faccount%2F"),
		Email:    email,
		Fetcher:  gmail,
	}, nil)
	slog.Info("gfiber-pusher: autoheal armed", "email", email, "min_interval", minInterval, "ledger", os.Getenv("GFIBER_AUTOHEAL_LEDGER"))
	return &gfiber.Heal{
		Mint:        auth0.Mint,
		CookieFile:  cookieFile,
		LedgerFile:  strings.TrimSpace(os.Getenv("GFIBER_AUTOHEAL_LEDGER")),
		MinInterval: minInterval,
	}, nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("gfiber-pusher: stopped", "err", err)
		os.Exit(1)
	}
}

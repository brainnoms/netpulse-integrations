// Headless re-authentication: the pusher re-mints its own portal session
// instead of waiting for a human to relay an e-mail code.
//
// The walk below was proven with curl (2026-11-27) against the live Auth0
// Universal Login for signin.gfiber.com — plain POSTs, no JS challenge:
//
//	GET  gfiber.com/account/auth/login?returnTo=/account/   307 -> /authorize (fresh PKCE+state)
//	GET  signin.gfiber.com/authorize?...                     302 -> /u/login/identifier?state=
//	GET  /u/login/identifier?state=                          200 form (state, username)
//	POST state+username                                      302 -> /u/login/password?state=
//	POST state+connection=email              ("request OTP") 302 -> /u/login/passwordless-email-challenge?state=
//	POST state+code+action=default           ("verify OTP")   302 -> callback chain -> __session__ pair on gfiber.com
//
// The one-time code is fetched from Gmail (see gmail.go), which makes the
// whole ritual human-free. A fresh login is a fresh Auth0 transaction: it
// mints its own session cookies and does not disturb the running jar until
// the walk succeeds and the caller swaps the cookies in.
package gfiber

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OTPFetcher returns the most recent one-time code received at or after
// notBefore. An empty string means "not delivered yet"; an error is a
// transport failure the caller may retry within its poll window.
type OTPFetcher interface {
	LatestCode(ctx context.Context, notBefore time.Time) (string, error)
}

// Auth0Config configures the headless login walk.
type Auth0Config struct {
	// LoginURL is the app's login entry that mints a fresh Auth0
	// transaction (PKCE challenge + state are generated there).
	LoginURL string
	// Email is the account identifier (the portal's #username field).
	Email string
	// Fetcher reads the code e-mail (Gmail API in production).
	Fetcher OTPFetcher
	// PollEvery / PollMax / ResendAt pace the code wait: one Gmail poll
	// per PollEvery up to PollMax, with a single resend at ResendAt.
	PollEvery time.Duration
	PollMax   time.Duration
	ResendAt  time.Duration
	// HTTPClient is optional (tests); redirects are not followed
	// automatically regardless, the walk hops manually to keep the
	// cookie jar authoritative on every leg.
	HTTPClient *http.Client
}

// Auth0 re-mints the portal session without a human.
type Auth0 struct {
	cfg    Auth0Config
	log    *slog.Logger
	client *http.Client
	jar    *cookiejar.Jar
}

// NewAuth0 prepares a walker. The returned Auth0 is reusable across deaths
// (each Mint starts a fresh transaction and jar).
func NewAuth0(cfg Auth0Config, log *slog.Logger) *Auth0 {
	if cfg.LoginURL == "" {
		cfg.LoginURL = "https://gfiber.com/account/auth/login?returnTo=%2Faccount%2F"
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 10 * time.Second
	}
	if cfg.PollMax == 0 {
		cfg.PollMax = 90 * time.Second
	}
	if cfg.ResendAt == 0 {
		cfg.ResendAt = 45 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &Auth0{cfg: cfg, log: log}
}

var stateRe = regexp.MustCompile(`name="state" value="([^"]+)"`)

// Mint walks the full identifier -> request-otp -> verify-otp flow and
// returns the freshly minted portal session cookies (__session__N).
func (a *Auth0) Mint(ctx context.Context) (map[string]string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("gfiber: cookie jar: %w", err)
	}
	hc := a.cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	cc := *hc
	client := &cc
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// 1. App login route -> 307 authorize URL (fresh state + PKCE).
	loc, err := a.hop(ctx, client, a.cfg.LoginURL)
	if err != nil {
		return nil, err
	}
	// 2. /authorize -> 302 identifier page.
	loc, err = a.hop(ctx, client, loc)
	if err != nil {
		return nil, err
	}
	// 3. Identifier page (200): harvest the transaction state.
	idenURL, body, err := a.getPage(ctx, client, loc)
	if err != nil {
		return nil, fmt.Errorf("gfiber: login identifier page: %w", err)
	}
	state := firstMatch(stateRe, body)
	if state == "" {
		return nil, fmt.Errorf("gfiber: login page carries no Auth0 state")
	}
	// 4. Identifier POST -> 302 password page.
	loc, err = a.post(ctx, client, idenURL, url.Values{
		"state":    []string{state},
		"username": []string{a.cfg.Email},
	})
	if err != nil {
		return nil, fmt.Errorf("gfiber: identifier: %w", err)
	}
	// 5. Password page GET (mirrors the browser; state is unchanged).
	pwURL, _, err := a.getPage(ctx, client, loc)
	if err != nil {
		return nil, fmt.Errorf("gfiber: password page: %w", err)
	}
	// 6. "Email me a one-time code": state + connection=email -> 302
	// challenge page. Everything after sendAt is this walk's e-mail.
	sendAt := time.Now()
	chalLoc, err := a.post(ctx, client, pwURL, url.Values{
		"state":      []string{state},
		"connection": []string{"email"},
	})
	if err != nil {
		return nil, fmt.Errorf("gfiber: otp request: %w", err)
	}
	chalURL, _, err := a.getPage(ctx, client, chalLoc)
	if err != nil {
		return nil, fmt.Errorf("gfiber: code page: %w", err)
	}
	// 7. Wait for the code; resend once at ResendAt, never twice.
	code, err := a.awaitCode(ctx, client, chalURL, state, sendAt)
	if err != nil {
		return nil, err
	}
	// 8. Verify. The callback chain mints the portal __session__ pair.
	loc, err = a.post(ctx, client, chalURL, url.Values{
		"state":  []string{state},
		"code":   []string{code},
		"action": []string{"default"},
	})
	if err != nil {
		return nil, fmt.Errorf("gfiber: otp verify rejected the code: %w", err)
	}
	for hops := 0; loc != ""; hops++ {
		if hops > 12 {
			return nil, fmt.Errorf("gfiber: callback chain did not settle")
		}
		loc, err = a.hop(ctx, client, loc)
		if err != nil {
			return nil, fmt.Errorf("gfiber: callback: %w", err)
		}
	}
	// 9. Harvest the session cookies the app minted on the portal host.
	u, err := url.Parse(a.cfg.LoginURL)
	if err != nil {
		return nil, err
	}
	cookies := map[string]string{}
	for _, c := range jar.Cookies(u) {
		if strings.HasPrefix(c.Name, "__session__") {
			cookies[c.Name] = c.Value
		}
	}
	if len(cookies) == 0 {
		return nil, fmt.Errorf("gfiber: walk finished with no __session__ cookie (login rejected?)")
	}
	return cookies, nil
}

// awaitCode polls the fetcher per the configured pace, resending the e-mail
// exactly once at ResendAt (Auth0 rate limits argue against more).
func (a *Auth0) awaitCode(ctx context.Context, client *http.Client, chalURL, state string, sendAt time.Time) (string, error) {
	deadline := time.NewTimer(a.cfg.PollMax)
	defer deadline.Stop()
	tick := time.NewTicker(a.cfg.PollEvery)
	defer tick.Stop()
	resent := false
	var lastErr error
	for {
		code, err := a.cfg.Fetcher.LatestCode(ctx, sendAt)
		if err != nil {
			lastErr = err
			a.log.Warn("gfiber: gmail poll failed", "err", err)
		} else if code != "" {
			return code, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			if !resent {
				resent = true
				_, rerr := a.post(ctx, client, chalURL, url.Values{
					"state": []string{state}, "action": []string{"resend"},
				})
				if rerr == nil {
					a.log.Warn("gfiber: code not seen, resent the e-mail once")
					deadline.Reset(a.cfg.PollMax)
					continue
				}
				a.log.Warn("gfiber: code resend failed", "err", rerr)
			}
			if lastErr != nil {
				return "", fmt.Errorf("gfiber: no one-time code within %v (last gmail error: %w)", 2*a.cfg.PollMax, lastErr)
			}
			return "", fmt.Errorf("gfiber: no one-time code within %v of the request", 2*a.cfg.PollMax)
		case <-tick.C:
			if !resent && time.Since(sendAt) >= a.cfg.ResendAt {
				resent = true
				if _, rerr := a.post(ctx, client, chalURL, url.Values{
					"state": []string{state}, "action": []string{"resend"},
				}); rerr == nil {
					a.log.Info("gfiber: code slow, resent the e-mail")
				}
			}
		}
	}
}

// hop GETs u and returns the resolved Location ("" when the response is not
// a redirect). Bodies are drained; cookies land in the jar either way.
func (a *Auth0) hop(ctx context.Context, client *http.Client, u string) (string, error) {
	res, err := a.getNoRedirect(ctx, client, u)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return res.Request.URL.ResolveReference(mustParseRef(res.Header.Get("location"))).String(), nil
	}
	return "", nil // caller inspects via subsequent getPage
}

// getPage GETs a page expected to render (200) and returns its final URL
// plus body. A redirect answer is followed once (transactions occasionally
// answer the first GET with a hop).
func (a *Auth0) getPage(ctx context.Context, client *http.Client, u string) (string, string, error) {
	res, err := a.getNoRedirect(ctx, client, u)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()
	if loc := res.Header.Get("location"); res.StatusCode >= 300 && res.StatusCode < 400 && loc != "" {
		next := res.Request.URL.ResolveReference(mustParseRef(loc)).String()
		res2, err := a.getNoRedirect(ctx, client, next)
		if err != nil {
			return "", "", err
		}
		defer res2.Body.Close()
		b, err := io.ReadAll(io.LimitReader(res2.Body, 2<<20))
		return res2.Request.URL.String(), string(b), err
	}
	if res.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d for %s", res.StatusCode, u)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	return res.Request.URL.String(), string(b), err
}

// post submits a form and returns the resolved Location of the 302 answer
// ("" when the response is not a redirect).
func (a *Auth0) post(ctx context.Context, client *http.Client, u string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gfiber: POST %s: %w", u, err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		if loc := res.Header.Get("location"); loc != "" {
			return res.Request.URL.ResolveReference(mustParseRef(loc)).String(), nil
		}
	}
	if res.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d for %s", res.StatusCode, u)
	}
	return "", nil
}

func (a *Auth0) getNoRedirect(ctx context.Context, client *http.Client, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gfiber: GET %s: %w", u, err)
	}
	return res, nil
}

func mustParseRef(s string) *url.URL { u, _ := url.Parse(s); return u }

func firstMatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

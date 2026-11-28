// Gmail API retrieval of the Auth0 one-time code.
//
// The portal login is Google-identity (no password), so the code lands in
// bob.minowicz@gmail.com. The pusher reads it with an OAuth2 refresh token
// (Google Cloud project, the mailbox is the only test user) — no IMAP, no
// passwords, service-account-incompatible mailbox semantics aside: the
// refresh token acts as the user and needs only gmail.readonly.
package gfiber

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GoogleCreds is the OAuth2 material for the mailbox: a client (downloaded
// client_secret.json shape, flat or nested under "installed"/"web") plus the
// long-lived refresh token the owner minted once via the consent flow.
type GoogleCreds struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
}

// LoadGoogleCreds reads the credentials JSON. Both hand-written flat files
// and gcloud's wrapped downloads are accepted; the refresh token is
// mandatory (it is the whole point of the file).
func LoadGoogleCreds(path string) (GoogleCreds, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GoogleCreds{}, fmt.Errorf("gfiber: google creds: %w", err)
	}
	var f struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		Installed    *struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"installed"`
		Web *struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"web"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return GoogleCreds{}, fmt.Errorf("gfiber: google creds: %w", err)
	}
	c := GoogleCreds{ClientID: f.ClientID, ClientSecret: f.ClientSecret, RefreshToken: f.RefreshToken}
	if (c.ClientID == "" || c.ClientSecret == "") && f.Installed != nil && f.Installed.ClientID != "" {
		c.ClientID, c.ClientSecret = f.Installed.ClientID, f.Installed.ClientSecret
	}
	if (c.ClientID == "" || c.ClientSecret == "") && f.Web != nil && f.Web.ClientID != "" {
		c.ClientID, c.ClientSecret = f.Web.ClientID, f.Web.ClientSecret
	}
	if c.ClientID == "" || c.ClientSecret == "" || c.RefreshToken == "" {
		return GoogleCreds{}, fmt.Errorf("gfiber: google creds need client_id, client_secret and refresh_token")
	}
	return c, nil
}

// Gmail fetches one-time-code e-mails over the Gmail REST API.
type Gmail struct {
	Creds GoogleCreds
	// TokenURL / APIBase are overridable for tests.
	TokenURL string
	APIBase  string
	// Query is the Gmail search locating the code e-mail. Kept broad on
	// purpose (sender hint + phrase); override via GFIBER_GMAIL_QUERY if
	// Auth0 changes its mail template.
	Query string
	HTTP  *http.Client

	token  string
	tokExp time.Time
}

// NewGmail prepares a fetcher with the production endpoints and the query
// learned from the human-relay ritual (Auth0 mails the one-time code).
func NewGmail(c GoogleCreds) *Gmail {
	return &Gmail{
		Creds:    c,
		TokenURL: "https://oauth2.googleapis.com/token",
		APIBase:  "https://gmail.googleapis.com",
		Query:    `from:auth0 "one-time"`,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
	}
}

var otpRe = regexp.MustCompile(`\b(\d{6})\b`)

// LatestCode returns the newest six-digit code mailed at or after
// notBefore, or "" while nothing matches yet.
func (g *Gmail) LatestCode(ctx context.Context, notBefore time.Time) (string, error) {
	tok, err := g.accessToken(ctx)
	if err != nil {
		return "", err
	}
	mins := int(time.Since(notBefore).Minutes()) + 1
	if mins < 1 {
		mins = 1
	}
	if mins > 1440 {
		mins = 1440
	}
	q := fmt.Sprintf(`%s newer_than:%dm`, g.Query, mins)
	var list struct {
		Messages []struct {
			ID           string `json:"id"`
			InternalDate string `json:"internalDate"`
		} `json:"messages"`
	}
	if err := g.apiGet(ctx, tok, "/gmail/v1/users/me/messages",
		url.Values{"q": {q}, "maxResults": {"5"}}, &list); err != nil {
		return "", err
	}
	if len(list.Messages) == 0 {
		return "", nil
	}
	// Never trust messages.list ordering: date-sorted (newer_than) answers
	// carry no documented direction, and after a resend two codes sit in
	// the window — only the newest still verifies at Auth0. Pick by
	// internalDate among messages at or after notBefore; a previous
	// episode's unread code is filtered by that same bound.
	chosen := ""
	var chosenAt time.Time
	first := ""
	for _, m := range list.Messages {
		if first == "" {
			first = m.ID
		}
		stamp, err := strconv.ParseInt(m.InternalDate, 10, 64)
		if err != nil {
			continue
		}
		at := time.UnixMilli(stamp)
		if at.Before(notBefore) {
			continue
		}
		if chosen == "" || at.After(chosenAt) {
			chosen, chosenAt = m.ID, at
		}
	}
	if chosen == "" {
		// No parseable date (thin stub answers): fall back to the first
		// hit and let the full-message timestamp guard below decide.
		chosen = first
	}
	var msg struct {
		InternalDate string `json:"internalDate"`
		Snippet      string `json:"snippet"`
		Payload      struct {
			MimeType string `json:"mimeType"`
			Body     struct {
				Data string `json:"data"`
			} `json:"body"`
			Parts []struct {
				MimeType string `json:"mimeType"`
				Body     struct {
					Data string `json:"data"`
				} `json:"body"`
			} `json:"parts"`
		} `json:"payload"`
	}
	if err := g.apiGet(ctx, tok, "/gmail/v1/users/me/messages/"+chosen,
		url.Values{"format": {"full"}}, &msg); err != nil {
		return "", err
	}
	if stamp, err := strconv.ParseInt(msg.InternalDate, 10, 64); err == nil && time.UnixMilli(stamp).Before(notBefore) {
		return "", nil
	}
	if m := otpRe.FindStringSubmatch(msg.Snippet); m != nil {
		return m[1], nil
	}
	texts := []string{}
	if msg.Payload.Body.Data != "" {
		texts = append(texts, decodeB64URL(msg.Payload.Body.Data))
	}
	for _, p := range msg.Payload.Parts {
		if p.Body.Data == "" {
			continue
		}
		if strings.HasPrefix(p.MimeType, "text/plain") {
			texts = append(texts, decodeB64URL(p.Body.Data))
		} else if len(texts) == 0 {
			texts = append(texts, decodeB64URL(p.Body.Data))
		}
	}
	for _, t := range texts {
		if m := otpRe.FindStringSubmatch(t); m != nil {
			return m[1], nil
		}
	}
	return "", nil
}

func decodeB64URL(s string) string {
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return ""
}

// accessToken exchanges the refresh token, cached until 60 s before expiry.
func (g *Gmail) accessToken(ctx context.Context) (string, error) {
	if g.token != "" && time.Now().Before(g.tokExp) {
		return g.token, nil
	}
	form := url.Values{
		"client_id":     {g.Creds.ClientID},
		"client_secret": {g.Creds.ClientSecret},
		"refresh_token": {g.Creds.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	res, err := g.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("gfiber: gmail token: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gfiber: gmail token: HTTP %d: %.200s", res.StatusCode, b)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		return "", fmt.Errorf("gfiber: gmail token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("gfiber: gmail token: empty access_token")
	}
	g.token = tok.AccessToken
	g.tokExp = time.Now().Add(time.Duration(tok.ExpiresIn-60) * time.Second)
	return g.token, nil
}

func (g *Gmail) apiGet(ctx context.Context, tok, path string, q url.Values, out any) error {
	u := g.APIBase + path + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+tok)
	res, err := g.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("gfiber: gmail %s: %w", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("gfiber: gmail %s: HTTP %d: %.200s", path, res.StatusCode, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("gfiber: gmail %s: decode: %w", path, err)
	}
	return nil
}

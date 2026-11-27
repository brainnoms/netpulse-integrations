// Package gfiber exposes the gFiber portal poller to the shared integrations
// supervisor while keeping the protocol implementation private.
package gfiber

import (
	"log/slog"

	internal "github.com/gnacho/netpulse-integrations/gfiber/internal/gfiber"
)

type Config = internal.Config
type Poller = internal.Poller
type SessionError = internal.SessionError
type Heal = internal.Heal
type Auth0 = internal.Auth0
type Auth0Config = internal.Auth0Config
type Gmail = internal.Gmail
type GoogleCreds = internal.GoogleCreds

var NewGmail = internal.NewGmail
var NewAuth0 = internal.NewAuth0
var LoadGoogleCreds = internal.LoadGoogleCreds

func New(cfg Config, loggers ...*slog.Logger) *Poller { return internal.New(cfg, loggers...) }

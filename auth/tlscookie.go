package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/hashicorp/go-multierror"

	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/SenseUnit/dumbproxy/tlsutil"
)

type sessionValidator interface {
	Valid(sessionID, _, userAddr string) bool
}

type TLSCookieAuth struct {
	logger   *clog.CondLogger
	stopOnce sync.Once
	next     Auth
	reject   Auth
	lookup   sessionValidator
}

func NewTLSCookieAuth(param_url *url.URL, logger *clog.CondLogger) (*TLSCookieAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	auth := &TLSCookieAuth{
		logger: logger,
	}
	if lookupURL := values.Get("lookup"); lookupURL == "" {
		return nil, errors.New("\"lookup\" parameter is mandatory for TLS cookie auth provider")
	} else {
		lookupAuth, err := NewAuth(lookupURL, logger)
		if err != nil {
			return nil, fmt.Errorf("unable to construct lookup provider for TLS cookie auth provider: %w", err)
		}
		lookup, ok := lookupAuth.(sessionValidator)
		if !ok {
			return nil, fmt.Errorf("unable to construct TLS cookie auth provider: provided lookup provider %q is not suitable for session validation", lookupURL)
		}
		auth.lookup = lookup
	}
	if nextAuth := values.Get("next"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.next = nap
	}
	if nextAuth := values.Get("else"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.reject = nap
	}
	return auth, nil
}

func (auth *TLSCookieAuth) Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	sessionID, ok := tlsutil.TLSSessionIDFromContext(ctx)
	if !ok {
		auth.logger.Debug("tlscookie: no session extracted for %s", req.RemoteAddr)
		return auth.handleReject(ctx, wr, req)
	}
	if !auth.lookup.Valid(hex.EncodeToString(sessionID[:]), "", req.RemoteAddr) {
		auth.logger.Info("tlscookie: session ID %x from %s is not permitted", sessionID, req.RemoteAddr)
		return auth.handleReject(ctx, wr, req)
	}
	if auth.next != nil {
		return auth.next.Validate(ctx, wr, req)
	}
	return fmt.Sprintf("tlscookie:%x", sessionID), true
}

func (auth *TLSCookieAuth) handleReject(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	if auth.reject != nil {
		return auth.reject.Validate(ctx, wr, req)
	}
	http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
	return "", false
}

func (auth *TLSCookieAuth) Close() error {
	var err error
	auth.stopOnce.Do(func() {
		if auth.next != nil {
			if closeErr := auth.next.Close(); closeErr != nil {
				err = multierror.Append(err, closeErr)
			}
		}
		if auth.reject != nil {
			if closeErr := auth.reject.Close(); closeErr != nil {
				err = multierror.Append(err, closeErr)
			}
		}
	})
	return err
}

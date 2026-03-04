// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// acmeError writes an RFC 8555 problem+json error response.
func acmeError(w http.ResponseWriter, status int, errType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   "urn:ietf:params:acme:error:" + errType,
		"detail": detail,
		"status": status,
	})
}

// --- URL Builders ---

func (srv *Server) orderURL(id string) string {
	return srv.cfg.ExternalURL + "/acme/order/" + id
}

func (srv *Server) authzURL(id string) string {
	return srv.cfg.ExternalURL + "/acme/authz/" + id
}

func (srv *Server) challengeURL(id string) string {
	return srv.cfg.ExternalURL + "/acme/challenge/" + id
}

func (srv *Server) finalizeURL(id string) string {
	return srv.cfg.ExternalURL + "/acme/order/" + id + "/finalize"
}

func (srv *Server) certURL(id string) string {
	return srv.cfg.ExternalURL + "/acme/certificate/" + id
}

func (srv *Server) accountURL(id string) string {
	return srv.cfg.ExternalURL + "/acme/account/" + id
}

// --- Helpers ---

func (srv *Server) getAuthzURLs(ctx context.Context, orderID string) ([]string, error) {
	authzs, err := srv.store.ListACMEAuthorizationsByOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}
	urls := make([]string, len(authzs))
	for i, a := range authzs {
		urls[i] = srv.authzURL(a.ID)
	}
	return urls, nil
}

func (srv *Server) renderOrder(order *store.ACMEOrder, authzURLs []string) map[string]interface{} {
	resp := map[string]interface{}{
		"status":         order.Status,
		"identifiers":    json.RawMessage(order.Identifiers),
		"authorizations": authzURLs,
		"finalize":       srv.finalizeURL(order.ID),
		"expires":        order.Expires.Format(time.RFC3339),
	}
	if order.CertificateURL != "" {
		resp["certificate"] = order.CertificateURL
	}
	if order.AssertionURL != "" {
		resp["assertionBundle"] = order.AssertionURL
	}
	if order.ErrorType != "" {
		resp["error"] = map[string]string{
			"type":   "urn:ietf:params:acme:error:" + order.ErrorType,
			"detail": order.ErrorDetail,
		}
	}
	return resp
}

func (srv *Server) renderChallenge(w http.ResponseWriter, ch *store.ACMEChallenge) {
	resp := map[string]interface{}{
		"type":   ch.Type,
		"url":    srv.challengeURL(ch.ID),
		"token":  ch.Token,
		"status": ch.Status,
	}
	if ch.Validated != nil {
		resp["validated"] = ch.Validated.Format(time.RFC3339)
	}
	if ch.ErrorType != "" {
		resp["error"] = map[string]string{
			"type":   "urn:ietf:params:acme:error:" + ch.ErrorType,
			"detail": ch.ErrorDetail,
		}
	}
	json.NewEncoder(w).Encode(resp)
}

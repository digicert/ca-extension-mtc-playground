package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

func (srv *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	dir := map[string]interface{}{
		"newNonce":   srv.cfg.ExternalURL + "/acme/new-nonce",
		"newAccount": srv.cfg.ExternalURL + "/acme/new-account",
		"newOrder":   srv.cfg.ExternalURL + "/acme/new-order",
		"meta": map[string]interface{}{
			"website":                 srv.cfg.ExternalURL,
			"externalAccountRequired": false,
		},
	}
	json.NewEncoder(w).Encode(dir)
}

func (srv *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead || r.Method == http.MethodPost {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (srv *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	hdr, payload, _, err := srv.verifyJWS(r, false)
	if err != nil {
		acmeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			acmeError(w, http.StatusBadRequest, "malformed", "invalid account request")
			return
		}
	}

	thumbprint, err := jwkThumbprint(hdr.JWK)
	if err != nil {
		acmeError(w, http.StatusBadRequest, "malformed", "invalid JWK")
		return
	}

	existing, err := srv.store.GetACMEAccountByThumbprint(r.Context(), thumbprint)
	if err == nil {
		w.Header().Set("Location", srv.accountURL(existing.ID))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  existing.Status,
			"contact": json.RawMessage(existing.Contact),
			"orders":  srv.cfg.ExternalURL + "/acme/account/" + existing.ID + "/orders",
		})
		return
	}

	if req.OnlyReturnExisting {
		acmeError(w, http.StatusBadRequest, "accountDoesNotExist", "account not found")
		return
	}

	contactJSON, _ := json.Marshal(req.Contact)
	acctID := newID()
	acct := &store.ACMEAccount{
		ID:            acctID,
		Status:        "valid",
		KeyThumbprint: thumbprint,
		JWK:           hdr.JWK,
		Contact:       contactJSON,
	}

	if err := srv.store.CreateACMEAccount(r.Context(), acct); err != nil {
		srv.logger.Error("acme: create account", "error", err)
		acmeError(w, http.StatusInternalServerError, "serverInternal", "failed to create account")
		return
	}

	srv.logger.Info("acme: account created", "id", acctID, "thumbprint", thumbprint)
	w.Header().Set("Location", srv.accountURL(acctID))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": req.Contact,
		"orders":  srv.cfg.ExternalURL + "/acme/account/" + acctID + "/orders",
	})
}

func (srv *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	_, payload, acct, err := srv.verifyJWS(r, true)
	if err != nil {
		acmeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		acmeError(w, http.StatusBadRequest, "malformed", "invalid order request")
		return
	}
	if len(req.Identifiers) == 0 {
		acmeError(w, http.StatusBadRequest, "malformed", "at least one identifier required")
		return
	}
	for _, ident := range req.Identifiers {
		if ident.Type != "dns" {
			acmeError(w, http.StatusBadRequest, "unsupportedIdentifier",
				fmt.Sprintf("identifier type %q not supported", ident.Type))
			return
		}
	}

	orderID := newID()
	identJSON, _ := json.Marshal(req.Identifiers)
	expires := time.Now().Add(srv.cfg.OrderExpiry)

	order := &store.ACMEOrder{
		ID:          orderID,
		AccountID:   acct.ID,
		Status:      "pending",
		Identifiers: identJSON,
		Expires:     expires,
	}

	var authzs []*store.ACMEAuthorization
	var challenges []*store.ACMEChallenge
	var authzURLs []string

	for _, ident := range req.Identifiers {
		authzID := newID()
		identSingle, _ := json.Marshal(ident)
		authz := &store.ACMEAuthorization{
			ID:         authzID,
			OrderID:    orderID,
			Identifier: identSingle,
			Status:     "pending",
			Expires:    expires,
			Wildcard:   strings.HasPrefix(ident.Value, "*."),
		}
		authzs = append(authzs, authz)
		authzURLs = append(authzURLs, srv.authzURL(authzID))

		challengeID := newID()
		token := newID() + newID()
		ch := &store.ACMEChallenge{
			ID:      challengeID,
			AuthzID: authzID,
			Type:    "http-01",
			Status:  "pending",
			Token:   token,
		}
		challenges = append(challenges, ch)
	}

	if err := srv.store.CreateACMEOrder(r.Context(), order, authzs, challenges); err != nil {
		srv.logger.Error("acme: create order", "error", err)
		acmeError(w, http.StatusInternalServerError, "serverInternal", "failed to create order")
		return
	}

	srv.logger.Info("acme: order created", "order_id", orderID, "account_id", acct.ID)
	w.Header().Set("Location", srv.orderURL(orderID))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(srv.renderOrder(order, authzURLs))
}

func (srv *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	_, _, _, err := srv.verifyJWS(r, true)
	if err != nil {
		acmeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	orderID := r.PathValue("id")
	order, err := srv.store.GetACMEOrder(r.Context(), orderID)
	if err != nil {
		acmeError(w, http.StatusNotFound, "orderNotFound", "order not found")
		return
	}

	authzURLs, err := srv.getAuthzURLs(r.Context(), orderID)
	if err != nil {
		acmeError(w, http.StatusInternalServerError, "serverInternal", "failed to load authorizations")
		return
	}

	json.NewEncoder(w).Encode(srv.renderOrder(order, authzURLs))
}

func (srv *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	_, _, _, err := srv.verifyJWS(r, true)
	if err != nil {
		acmeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	authzID := r.PathValue("id")
	authz, err := srv.store.GetACMEAuthorization(r.Context(), authzID)
	if err != nil {
		acmeError(w, http.StatusNotFound, "authorizationNotFound", "authorization not found")
		return
	}

	challenges, err := srv.store.ListACMEChallengesByAuthz(r.Context(), authzID)
	if err != nil {
		acmeError(w, http.StatusInternalServerError, "serverInternal", "failed to load challenges")
		return
	}

	var chRender []map[string]interface{}
	for _, ch := range challenges {
		chMap := map[string]interface{}{
			"type":   ch.Type,
			"url":    srv.challengeURL(ch.ID),
			"token":  ch.Token,
			"status": ch.Status,
		}
		if ch.Validated != nil {
			chMap["validated"] = ch.Validated.Format(time.RFC3339)
		}
		chRender = append(chRender, chMap)
	}

	resp := map[string]interface{}{
		"status":     authz.Status,
		"identifier": json.RawMessage(authz.Identifier),
		"challenges": chRender,
		"expires":    authz.Expires.Format(time.RFC3339),
	}
	if authz.Wildcard {
		resp["wildcard"] = true
	}
	json.NewEncoder(w).Encode(resp)
}

func (srv *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	_, _, acct, err := srv.verifyJWS(r, true)
	if err != nil {
		acmeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	challengeID := r.PathValue("id")
	ch, err := srv.store.GetACMEChallenge(r.Context(), challengeID)
	if err != nil {
		acmeError(w, http.StatusNotFound, "challengeNotFound", "challenge not found")
		return
	}

	if ch.Status == "valid" || ch.Status == "invalid" {
		srv.renderChallenge(w, ch)
		return
	}

	go srv.validateChallenge(context.Background(), ch, acct)
	ch.Status = "processing"
	srv.renderChallenge(w, ch)
}

func (srv *Server) validateChallenge(ctx context.Context, ch *store.ACMEChallenge, acct *store.ACMEAccount) {
	now := time.Now()

	if srv.cfg.AutoApproveChallenge {
		if err := srv.store.UpdateACMEChallengeStatus(ctx, ch.ID, "valid", &now, "", ""); err != nil {
			srv.logger.Error("acme: update challenge status", "error", err)
			return
		}
	} else {
		thumbprint, _ := jwkThumbprint(acct.JWK)
		keyAuthz := ch.Token + "." + thumbprint
		err := srv.performHTTP01(ctx, ch, keyAuthz)
		if err != nil {
			srv.logger.Warn("acme: http-01 validation failed", "challenge", ch.ID, "error", err)
			srv.store.UpdateACMEChallengeStatus(ctx, ch.ID, "invalid", nil, "unauthorized", err.Error())
			return
		}
		if err := srv.store.UpdateACMEChallengeStatus(ctx, ch.ID, "valid", &now, "", ""); err != nil {
			srv.logger.Error("acme: update challenge status", "error", err)
			return
		}
	}

	authz, err := srv.store.GetACMEAuthorization(ctx, ch.AuthzID)
	if err != nil {
		srv.logger.Error("acme: get authz for challenge", "error", err)
		return
	}
	if err := srv.store.UpdateACMEAuthorizationStatus(ctx, authz.ID, "valid"); err != nil {
		srv.logger.Error("acme: update authz status", "error", err)
		return
	}

	allAuthzs, err := srv.store.ListACMEAuthorizationsByOrder(ctx, authz.OrderID)
	if err != nil {
		return
	}
	allValid := true
	for _, a := range allAuthzs {
		if a.ID == authz.ID {
			continue
		}
		if a.Status != "valid" {
			allValid = false
			break
		}
	}
	if allValid {
		if err := srv.store.UpdateACMEOrderStatus(ctx, authz.OrderID, "ready", nil); err != nil {
			srv.logger.Error("acme: update order to ready", "error", err)
		} else {
			srv.logger.Info("acme: order ready", "order_id", authz.OrderID)
		}
	}
}

func (srv *Server) performHTTP01(ctx context.Context, ch *store.ACMEChallenge, keyAuthz string) error {
	authz, err := srv.store.GetACMEAuthorization(ctx, ch.AuthzID)
	if err != nil {
		return fmt.Errorf("get authz: %w", err)
	}
	var ident struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(authz.Identifier, &ident); err != nil {
		return fmt.Errorf("parse identifier: %w", err)
	}
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", ident.Value, ch.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 1024)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if strings.TrimSpace(string(body)) != keyAuthz {
		return fmt.Errorf("key authorization mismatch")
	}
	return nil
}

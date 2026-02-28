package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (srv *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	_, payload, acct, err := srv.verifyJWS(r, true)
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
	if order.AccountID != acct.ID {
		acmeError(w, http.StatusForbidden, "unauthorized", "order does not belong to account")
		return
	}
	if order.Status != "ready" {
		acmeError(w, http.StatusForbidden, "orderNotReady",
			fmt.Sprintf("order status is %q, expected \"ready\"", order.Status))
		return
	}

	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		acmeError(w, http.StatusBadRequest, "malformed", "invalid finalize request")
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		acmeError(w, http.StatusBadRequest, "badCSR", "invalid CSR encoding")
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		acmeError(w, http.StatusBadRequest, "badCSR", "invalid CSR: "+err.Error())
		return
	}

	var orderIdents []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	json.Unmarshal(order.Identifiers, &orderIdents)

	csrNames := make(map[string]bool)
	if csr.Subject.CommonName != "" {
		csrNames[strings.ToLower(csr.Subject.CommonName)] = true
	}
	for _, name := range csr.DNSNames {
		csrNames[strings.ToLower(name)] = true
	}
	for _, ident := range orderIdents {
		if !csrNames[strings.ToLower(ident.Value)] {
			acmeError(w, http.StatusBadRequest, "badCSR",
				fmt.Sprintf("CSR missing identifier %q", ident.Value))
			return
		}
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := srv.store.UpdateACMEOrderStatus(r.Context(), orderID, "processing", map[string]interface{}{
		"csr": string(csrPEM),
	}); err != nil {
		acmeError(w, http.StatusInternalServerError, "serverInternal", "failed to update order")
		return
	}

	srv.logger.Info("acme: order finalizing", "order_id", orderID, "cn", csr.Subject.CommonName)
	go srv.processFinalize(context.Background(), orderID, csr, csrPEM, orderIdents)

	order.Status = "processing"
	authzURLs, _ := srv.getAuthzURLs(r.Context(), orderID)
	w.Header().Set("Location", srv.orderURL(orderID))
	json.NewEncoder(w).Encode(srv.renderOrder(order, authzURLs))
}

func (srv *Server) processFinalize(ctx context.Context, orderID string, csr *x509.CertificateRequest, csrPEM []byte, idents []struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}) {
	serial, err := srv.proxyToCA(ctx, csr, csrPEM, idents)
	if err != nil {
		srv.logger.Error("acme: CA proxy failed", "order_id", orderID, "error", err)
		srv.store.UpdateACMEOrderStatus(ctx, orderID, "invalid", map[string]interface{}{
			"error_type":   "serverInternal",
			"error_detail": "CA issuance failed: " + err.Error(),
		})
		return
	}

	srv.logger.Info("acme: cert issued via CA", "order_id", orderID, "serial", serial)
	srv.store.UpdateACMEOrderStatus(ctx, orderID, "processing", map[string]interface{}{
		"cert_serial": serial,
	})

	assertionURL, err := srv.waitForAssertion(ctx, serial)
	if err != nil {
		srv.logger.Warn("acme: assertion wait failed", "order_id", orderID, "error", err)
		srv.store.UpdateACMEOrderStatus(ctx, orderID, "valid", map[string]interface{}{
			"certificate_url": srv.certURL(orderID),
		})
		return
	}

	srv.logger.Info("acme: assertion ready", "order_id", orderID, "assertion_url", assertionURL)
	srv.store.UpdateACMEOrderStatus(ctx, orderID, "valid", map[string]interface{}{
		"certificate_url": srv.certURL(orderID),
		"assertion_url":   assertionURL,
	})
}

func (srv *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	_, _, acct, err := srv.verifyJWS(r, true)
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
	if order.AccountID != acct.ID {
		acmeError(w, http.StatusForbidden, "unauthorized", "order does not belong to account")
		return
	}
	if order.Status != "valid" {
		acmeError(w, http.StatusForbidden, "orderNotReady", "certificate not yet available")
		return
	}
	if order.CertSerial == "" {
		acmeError(w, http.StatusNotFound, "orderNotFound", "no certificate serial")
		return
	}

	idx, err := srv.store.FindEntryBySerial(r.Context(), order.CertSerial)
	if err != nil {
		acmeError(w, http.StatusNotFound, "orderNotFound", "certificate not found in log")
		return
	}
	entry, err := srv.store.GetEntry(r.Context(), idx)
	if err != nil {
		acmeError(w, http.StatusInternalServerError, "serverInternal", "failed to retrieve certificate")
		return
	}

	certDER := entry.EntryData
	if len(certDER) > 6 {
		entryLen := int(certDER[2]) | int(certDER[3])<<8 | int(certDER[4])<<16 | int(certDER[5])<<24
		if 6+entryLen <= len(certDER) {
			certDER = certDER[6 : 6+entryLen]
		}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if order.AssertionURL != "" {
		ab, abErr := srv.store.GetAssertionBundleBySerial(r.Context(), order.CertSerial)
		if abErr == nil {
			certPEM = append(certPEM, '\n')
			certPEM = append(certPEM, []byte(ab.BundlePEM)...)
		}
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(certPEM)
}

// proxyToCA sends a CSR to the DigiCert Private CA and returns the issued certificate serial.
func (srv *Server) proxyToCA(ctx context.Context, csr *x509.CertificateRequest, csrPEM []byte, idents []struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}) (string, error) {
	var dnsNames []string
	for _, id := range idents {
		dnsNames = append(dnsNames, id.Value)
	}

	cn := csr.Subject.CommonName
	if cn == "" && len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	org := "ACME Client"
	if len(csr.Subject.Organization) > 0 {
		org = csr.Subject.Organization[0]
	}
	country := "US"
	if len(csr.Subject.Country) > 0 {
		country = csr.Subject.Country[0]
	}

	payload := map[string]interface{}{
		"issuer":      map[string]string{"id": srv.cfg.CAID},
		"template_id": srv.cfg.TemplateID,
		"cert_type":   "private_ssl",
		"csr":         string(csrPEM),
		"subject": map[string]string{
			"common_name":       cn,
			"organization_name": org,
			"country":           country,
		},
		"validity": map[string]string{
			"valid_from": time.Now().UTC().Format(time.RFC3339),
			"valid_to":   time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		},
		"extensions": map[string]interface{}{
			"san": map[string]interface{}{
				"dns_names": dnsNames,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal CA request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.cfg.CAProxyURL+"/certificate-authority/api/v1/certificate",
		strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("create CA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", srv.cfg.CAAPIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("CA request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read CA response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("CA returned %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp struct {
		ID           string `json:"id"`
		SerialNumber string `json:"serial_number"`
	}
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return "", fmt.Errorf("parse CA response: %w", err)
	}
	if certResp.SerialNumber == "" {
		return "", fmt.Errorf("CA returned empty serial number")
	}

	return strings.ToUpper(certResp.SerialNumber), nil
}

// waitForAssertion polls the store for an assertion bundle matching the given serial.
func (srv *Server) waitForAssertion(ctx context.Context, serial string) (string, error) {
	deadline := time.After(srv.cfg.AssertionTimeout)
	ticker := time.NewTicker(srv.cfg.AssertionPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return "", fmt.Errorf("timeout waiting for assertion bundle for serial %s", serial)
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			idx, err := srv.store.FindEntryBySerial(ctx, serial)
			if err != nil {
				continue
			}
			ab, err := srv.store.GetAssertionBundle(ctx, idx)
			if err != nil {
				continue
			}
			if ab.Stale {
				continue
			}
			return srv.cfg.MTCBridgeURL + "/assertion/" + serial, nil
		}
	}
}

// readLimited reads up to n bytes from r.
func readLimited(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

// GetOrderCount returns the total number of ACME orders.
func (srv *Server) GetOrderCount(ctx context.Context) (int64, error) {
	var count int64
	err := srv.store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_orders").Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetAccountCount returns the total number of ACME accounts.
func (srv *Server) GetAccountCount(ctx context.Context) (int64, error) {
	var count int64
	err := srv.store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_accounts").Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

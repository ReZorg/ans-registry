// Package ra implements the Registration Authority (RA) for the ANS registry.
//
// The RA validates registration requests, issues simulated identity and server
// certificates, generates DNS record content, and seals lifecycle events into
// the Transparency Log.
package ra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/store"
	"github.com/ReZorg/ans-registry/internal/tl"
)

// validSemver matches "major.minor.patch" with no pre-release or build suffix.
var validSemver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// maxHostLen is the 237-octet FQDN limit defined in §3.1.
const maxHostLen = 237

// RA is the Registration Authority service.
type RA struct {
	store  *store.Store
	tl     *tl.Log
	raID   string
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

// New creates an RA instance, initialising an in-process private CA.
func New(s *store.Store, log *tl.Log) (*RA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caCert, err := selfSignedCA(caKey)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	return &RA{
		store:  s,
		tl:     log,
		raID:   "ra-" + uuid.New().String(),
		caKey:  caKey,
		caCert: caCert,
	}, nil
}

// RAID returns the stable identifier of this RA instance.
func (r *RA) RAID() string { return r.raID }

// Register validates the request, creates the registration record (PENDING →
// ACTIVE), issues certificates, generates DNS records, and seals an
// AGENT_REGISTERED event into the TL.
func (r *RA) Register(req *models.RegistrationRequest) (*models.Registration, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}

	ansName := buildANSName(req.Version, req.AgentHost)
	agentID := uuid.New().String()
	providerID := deriveProviderID(req.AgentHost)

	now := time.Now().UTC()
	certExpiry := now.Add(365 * 24 * time.Hour)

	// Issue Identity Certificate (Private CA, URI SAN = ansName).
	identityCertPEM, err := r.issueIdentityCert(ansName, certExpiry)
	if err != nil {
		return nil, fmt.Errorf("issue identity certificate: %w", err)
	}

	// Issue or accept Server Certificate.
	var serverCertPEM string
	if req.ServerCertPEM != "" {
		serverCertPEM = req.ServerCertPEM
	} else {
		serverCertPEM, err = r.issueServerCert(req.AgentHost, certExpiry)
		if err != nil {
			return nil, fmt.Errorf("issue server certificate: %w", err)
		}
	}

	// Hash Registration Metadata if provided.
	var cardHash string
	if req.AgentCardContent != nil {
		cardHash, err = hashJSON(req.AgentCardContent)
		if err != nil {
			return nil, fmt.Errorf("hash agent card: %w", err)
		}
	}

	// Generate DNS records.
	dnsRecords := r.generateDNSRecords(req, agentID, serverCertPEM)

	reg := &models.Registration{
		AgentID:          agentID,
		ANSName:          ansName,
		AgentDisplayName: req.AgentDisplayName,
		AgentDescription: req.AgentDescription,
		Version:          req.Version,
		AgentHost:        req.AgentHost,
		Endpoints:        req.Endpoints,
		IdentityCertPEM:  identityCertPEM,
		ServerCertPEM:    serverCertPEM,
		Status:           models.StatusActive,
		ProviderID:       providerID,
		LEI:              req.LEI,
		RAID:             r.raID,
		AgentCardContent: req.AgentCardContent,
		AgentCardHash:    cardHash,
		ECHConfigList:    req.ECHConfigList,
		IssuedAt:         now,
		ExpiresAt:        certExpiry,
		DNSRecords:       dnsRecords,
	}

	if err := r.store.SaveRegistration(reg); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, &ConflictError{ANSName: ansName}
		}
		return nil, fmt.Errorf("save registration: %w", err)
	}

	// Seal into TL.
	event := r.buildRegistrationEvent(reg)
	entry, err := r.tl.SealEvent(agentID, event)
	if err != nil {
		return nil, fmt.Errorf("seal TL event: %w", err)
	}

	reg.LogEntryID = entry.LogID
	if err := r.store.SaveRegistration(reg); err != nil {
		return nil, fmt.Errorf("update log entry ID: %w", err)
	}

	return reg, nil
}

// Revoke revokes the named registration and seals an AGENT_REVOKED event.
func (r *RA) Revoke(agentID string, req *models.RevocationRequest) (*models.RevocationResponse, error) {
	reg, err := r.store.GetRegistration(agentID)
	if err != nil {
		return nil, err
	}
	if reg.Status == models.StatusRevoked {
		// Revocation is idempotent.
		return buildRevocationResponse(reg, req.Reason), nil
	}
	if reg.Status == models.StatusExpired {
		return nil, &ValidationError{Field: "status", Msg: "cannot revoke an expired registration"}
	}

	now := time.Now().UTC()
	reg.Status = models.StatusRevoked
	if err := r.store.SaveRegistration(reg); err != nil {
		return nil, fmt.Errorf("save revoked registration: %w", err)
	}

	event := r.buildRevocationEvent(reg, req.Reason, now)
	if _, err := r.tl.SealEvent(agentID, event); err != nil {
		return nil, fmt.Errorf("seal revocation event: %w", err)
	}

	return buildRevocationResponse(reg, req.Reason), nil
}

// UpdateECH updates the ECH config of a registration without creating a TL event.
func (r *RA) UpdateECH(agentID, echConfigList string) (*models.Registration, error) {
	reg, err := r.store.GetRegistration(agentID)
	if err != nil {
		return nil, err
	}
	if reg.Status != models.StatusActive {
		return nil, &ValidationError{Field: "status", Msg: "ECH update requires ACTIVE status"}
	}
	reg.ECHConfigList = echConfigList
	if err := r.store.SaveRegistration(reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// --- Validation ---

// ValidationError is returned when input fields fail validation rules.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on %s: %s", e.Field, e.Msg)
}

// ConflictError is returned when an ANSName is already registered.
type ConflictError struct {
	ANSName string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("ANSName already registered: %s", e.ANSName)
}

func validateRequest(req *models.RegistrationRequest) error {
	if strings.TrimSpace(req.AgentDisplayName) == "" {
		return &ValidationError{Field: "agentDisplayName", Msg: "required"}
	}
	if len(req.AgentDisplayName) > 64 {
		return &ValidationError{Field: "agentDisplayName", Msg: "must not exceed 64 characters"}
	}
	if req.AgentDescription != "" && len(req.AgentDescription) > 150 {
		return &ValidationError{Field: "agentDescription", Msg: "must not exceed 150 characters"}
	}
	if !validSemver.MatchString(req.Version) {
		return &ValidationError{Field: "version", Msg: "must be numeric semver major.minor.patch (e.g. 1.0.0)"}
	}
	if err := validateFQDN(req.AgentHost); err != nil {
		return err
	}
	if len(req.Endpoints) == 0 {
		return &ValidationError{Field: "endpoints", Msg: "at least one endpoint is required"}
	}
	for i, ep := range req.Endpoints {
		if err := validateEndpoint(i, ep); err != nil {
			return err
		}
	}
	if strings.TrimSpace(req.IdentityCSRPEM) == "" {
		return &ValidationError{Field: "identityCsrPEM", Msg: "required"}
	}
	return nil
}

func validateFQDN(host string) error {
	if host == "" {
		return &ValidationError{Field: "agentHost", Msg: "required"}
	}
	if len(host) > maxHostLen {
		return &ValidationError{Field: "agentHost", Msg: fmt.Sprintf("must not exceed %d octets", maxHostLen)}
	}
	// Each label: 1-63 chars, LDH, no leading/trailing hyphen.
	labelRe := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return &ValidationError{Field: "agentHost", Msg: "must be a fully qualified domain name with at least two labels"}
	}
	for _, label := range labels {
		if label == "" || !labelRe.MatchString(label) {
			return &ValidationError{Field: "agentHost", Msg: fmt.Sprintf("label %q is invalid (RFC 1035/1123)", label)}
		}
	}
	return nil
}

func validateEndpoint(idx int, ep models.Endpoint) error {
	field := func(s string) string { return fmt.Sprintf("endpoints[%d].%s", idx, s) }
	switch ep.Protocol {
	case models.ProtocolA2A, models.ProtocolMCP, models.ProtocolHTTPAPI:
	default:
		return &ValidationError{Field: field("protocol"), Msg: "must be A2A, MCP, or HTTP-API"}
	}
	if _, err := url.ParseRequestURI(ep.AgentURL); err != nil || ep.AgentURL == "" {
		return &ValidationError{Field: field("agentUrl"), Msg: "must be a valid URL"}
	}
	return nil
}

// --- Certificate helpers ---

func (r *RA) issueIdentityCert(ansName string, expiry time.Time) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   ansName,
			Organization: []string{"ANS Private CA"},
		},
		URIs:      []*url.URL{mustParseURL(ansName)},
		NotBefore: time.Now().UTC(),
		NotAfter:  expiry,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, r.caCert, &key.PublicKey, r.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})), nil
}

func (r *RA) issueServerCert(fqdn string, expiry time.Time) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   fqdn,
			Organization: []string{"ANS RA"},
		},
		DNSNames:  []string{fqdn},
		NotBefore: time.Now().UTC(),
		NotAfter:  expiry,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, r.caCert, &key.PublicKey, r.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})), nil
}

func selfSignedCA(key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "ANS Private CA"},
		NotBefore:             time.Now().UTC().Add(-time.Minute),
		NotAfter:              time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// --- DNS record generation ---

func (r *RA) generateDNSRecords(req *models.RegistrationRequest, agentID, serverCertPEM string) *models.DNSRecordSet {
	version := "v" + req.Version
	tlHost := "tl.ans.example" // placeholder; would come from config in production
	badgeURL := fmt.Sprintf("https://%s/v1/agents/%s", tlHost, agentID)
	cardURL := ""
	for _, ep := range req.Endpoints {
		if ep.MetadataURL != "" {
			cardURL = ep.MetadataURL
			break
		}
	}
	if cardURL == "" {
		cardURL = fmt.Sprintf("https://%s/.well-known/agent-card.json", req.AgentHost)
	}

	// Build _ans TXT records (one per protocol endpoint).
	var ansRecords []string
	for _, ep := range req.Endpoints {
		proto := strings.ToLower(string(ep.Protocol))
		rec := fmt.Sprintf("v=ans1; version=%s; p=%s; url=%s", version, proto, cardURL)
		ansRecords = append(ansRecords, rec)
	}
	if len(ansRecords) == 0 {
		ansRecords = []string{fmt.Sprintf("v=ans1; version=%s; url=%s", version, cardURL)}
	}

	// TLSA record content — SHA-256 of the server certificate DER.
	tlsaValue := certFingerprint(serverCertPEM)

	httpsValue := "1 . alpn=h2"
	if req.ECHConfigList != "" {
		httpsValue += " ech=" + req.ECHConfigList
	}

	return &models.DNSRecordSet{
		ANS:      ansRecords,
		ANSBadge: fmt.Sprintf("v=ans-badge1; version=%s; url=%s", version, badgeURL),
		HTTPS:    httpsValue,
		TLSA:     fmt.Sprintf("3 0 1 %s", tlsaValue),
	}
}

// certFingerprint returns the SHA-256 fingerprint of the first PEM certificate.
func certFingerprint(pemStr string) string {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// --- TL event builders ---

func (r *RA) buildRegistrationEvent(reg *models.Registration) models.TLEventPayload {
	return models.TLEventPayload{
		AnsID:     reg.AgentID,
		ANSName:   reg.ANSName,
		EventType: models.EventRegistered,
		Agent: models.TLAgentInfo{
			Host:       reg.AgentHost,
			Name:       reg.AgentDisplayName,
			Version:    "v" + reg.Version,
			ProviderID: reg.ProviderID,
			LEI:        reg.LEI,
		},
		Attestations: models.Attestations{
			IdentityCert: models.CertAttestation{
				Fingerprint: certFingerprint(reg.IdentityCertPEM),
				Type:        "X509-OV-CLIENT",
			},
			ServerCert: models.CertAttestation{
				Fingerprint: certFingerprint(reg.ServerCertPEM),
				Type:        "X509-DV-SERVER",
			},
			DNSRecordsProvisioned: *reg.DNSRecords,
			DomainValidation:      "ACME-DNS-01",
		},
		ExpiresAt: reg.ExpiresAt.Format(time.RFC3339),
		IssuedAt:  reg.IssuedAt.Format(time.RFC3339),
		RAID:      r.raID,
		Timestamp: reg.IssuedAt.Format(time.RFC3339),
	}
}

func (r *RA) buildRevocationEvent(reg *models.Registration, reason models.RevocationReason, now time.Time) models.TLEventPayload {
	e := r.buildRegistrationEvent(reg)
	e.EventType = models.EventRevoked
	e.RevocationReasonCode = reason
	e.RevokedAt = now.Format(time.RFC3339)
	e.Timestamp = now.Format(time.RFC3339)
	return e
}

// --- Misc helpers ---

func buildANSName(version, host string) string {
	return fmt.Sprintf("ans://v%s.%s", version, host)
}

func deriveProviderID(host string) string {
	// Stable per-host identifier: use a truncated SHA-256 of the FQDN.
	sum := sha256.Sum256([]byte(host))
	return "PID-" + hex.EncodeToString(sum[:4])
}

func hashJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "SHA256:" + hex.EncodeToString(sum[:]), nil
}

func buildRevocationResponse(reg *models.Registration, reason models.RevocationReason) *models.RevocationResponse {
	resp := &models.RevocationResponse{
		AgentID:   reg.AgentID,
		ANSName:   reg.ANSName,
		Status:    models.StatusRevoked,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
	}
	if reg.DNSRecords != nil {
		resp.DNSRecordsToRemove = buildDNSRemovalList(reg)
	}
	return resp
}

func buildDNSRemovalList(reg *models.Registration) []models.DNSRecord {
	var records []models.DNSRecord
	host := reg.AgentHost
	if reg.DNSRecords.HTTPS != "" {
		records = append(records, models.DNSRecord{
			Name:    host,
			Type:    "HTTPS",
			Value:   reg.DNSRecords.HTTPS,
			Purpose: "DISCOVERY",
		})
	}
	if reg.DNSRecords.TLSA != "" {
		records = append(records, models.DNSRecord{
			Name:    "_443._tcp." + host,
			Type:    "TLSA",
			Value:   reg.DNSRecords.TLSA,
			Purpose: "CERTIFICATE_BINDING",
		})
	}
	for _, rec := range reg.DNSRecords.ANS {
		records = append(records, models.DNSRecord{
			Name:    "_ans." + host,
			Type:    "TXT",
			Value:   rec,
			Purpose: "TRUST",
		})
	}
	if reg.DNSRecords.ANSBadge != "" {
		records = append(records, models.DNSRecord{
			Name:    "_ans-badge." + host,
			Type:    "TXT",
			Value:   reg.DNSRecords.ANSBadge,
			Purpose: "BADGE",
		})
	}
	return records
}

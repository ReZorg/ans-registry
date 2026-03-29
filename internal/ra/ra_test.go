package ra_test

import (
	"strings"
	"testing"

	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/ra"
	"github.com/ReZorg/ans-registry/internal/store"
	"github.com/ReZorg/ans-registry/internal/tl"
)

func newRA(t *testing.T) (*ra.RA, *store.Store) {
	t.Helper()
	s := store.New()
	l, err := tl.New(s)
	if err != nil {
		t.Fatalf("tl.New: %v", err)
	}
	reg, err := ra.New(s, l)
	if err != nil {
		t.Fatalf("ra.New: %v", err)
	}
	return reg, s
}

func validRequest() *models.RegistrationRequest {
	return &models.RegistrationRequest{
		AgentDisplayName: "Test Agent",
		AgentDescription: "A test agent.",
		Version:          "1.0.0",
		AgentHost:        "agent.example.com",
		Endpoints: []models.Endpoint{
			{
				Protocol: models.ProtocolA2A,
				AgentURL: "https://agent.example.com/a2a",
			},
		},
		IdentityCSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBTest\n-----END CERTIFICATE REQUEST-----",
	}
}

func TestRegisterSuccess(t *testing.T) {
	reg, s := newRA(t)
	req := validRequest()
	result, err := reg.Register(req)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if result.AgentID == "" {
		t.Error("expected non-empty AgentID")
	}
	if result.ANSName != "ans://v1.0.0.agent.example.com" {
		t.Errorf("ANSName = %q, want %q", result.ANSName, "ans://v1.0.0.agent.example.com")
	}
	if result.Status != models.StatusActive {
		t.Errorf("Status = %q, want ACTIVE", result.Status)
	}
	if result.IdentityCertPEM == "" {
		t.Error("expected Identity Certificate PEM")
	}
	if result.ServerCertPEM == "" {
		t.Error("expected Server Certificate PEM")
	}
	if result.LogEntryID == "" {
		t.Error("expected LogEntryID after sealing")
	}
	if result.DNSRecords == nil {
		t.Fatal("expected DNS records")
	}
	if len(result.DNSRecords.ANS) == 0 {
		t.Error("expected at least one _ans record")
	}
	if !strings.Contains(result.DNSRecords.ANSBadge, result.AgentID) {
		t.Errorf("_ans-badge record should reference agentId; got %q", result.DNSRecords.ANSBadge)
	}

	// Verify it's queryable.
	stored, err := s.GetRegistration(result.AgentID)
	if err != nil {
		t.Fatalf("GetRegistration: %v", err)
	}
	if stored.ANSName != result.ANSName {
		t.Errorf("stored ANSName = %q, want %q", stored.ANSName, result.ANSName)
	}
}

func TestRegisterDuplicateANSName(t *testing.T) {
	reg, _ := newRA(t)
	req := validRequest()
	if _, err := reg.Register(req); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	_, err := reg.Register(req)
	if err == nil {
		t.Fatal("expected conflict error on duplicate ANSName")
	}
	var ce *ra.ConflictError
	if !isConflictError(err, &ce) {
		t.Errorf("expected ConflictError, got %T: %v", err, err)
	}
}

func isConflictError(err error, target **ra.ConflictError) bool {
	if e, ok := err.(*ra.ConflictError); ok {
		*target = e
		return true
	}
	return false
}

func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name  string
		mutate func(*models.RegistrationRequest)
		wantErr string
	}{
		{"missing display name", func(r *models.RegistrationRequest) { r.AgentDisplayName = "" }, "agentDisplayName"},
		{"display name too long", func(r *models.RegistrationRequest) { r.AgentDisplayName = strings.Repeat("A", 65) }, "agentDisplayName"},
		{"description too long", func(r *models.RegistrationRequest) { r.AgentDescription = strings.Repeat("x", 151) }, "agentDescription"},
		{"invalid semver", func(r *models.RegistrationRequest) { r.Version = "1.0.0-beta" }, "version"},
		{"missing host", func(r *models.RegistrationRequest) { r.AgentHost = "" }, "agentHost"},
		{"invalid host label", func(r *models.RegistrationRequest) { r.AgentHost = "-bad.example.com" }, "agentHost"},
		{"no endpoints", func(r *models.RegistrationRequest) { r.Endpoints = nil }, "endpoints"},
		{"invalid endpoint protocol", func(r *models.RegistrationRequest) {
			r.Endpoints = []models.Endpoint{{Protocol: "SMTP", AgentURL: "https://x.example.com"}}
		}, "protocol"},
		{"invalid endpoint URL", func(r *models.RegistrationRequest) {
			r.Endpoints = []models.Endpoint{{Protocol: models.ProtocolA2A, AgentURL: "not-a-url"}}
		}, "agentUrl"},
		{"missing CSR", func(r *models.RegistrationRequest) { r.IdentityCSRPEM = "" }, "identityCsrPEM"},
	}

	reg, _ := newRA(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mutate(req)
			_, err := reg.Register(req)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRevokeAgent(t *testing.T) {
	reg, s := newRA(t)
	result, err := reg.Register(validRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	resp, err := reg.Revoke(result.AgentID, &models.RevocationRequest{
		Reason: models.ReasonCessationOfOperation,
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if resp.Status != models.StatusRevoked {
		t.Errorf("Status = %q, want REVOKED", resp.Status)
	}
	if len(resp.DNSRecordsToRemove) == 0 {
		t.Error("expected DNS records to remove")
	}

	// Verify persisted state.
	stored, _ := s.GetRegistration(result.AgentID)
	if stored.Status != models.StatusRevoked {
		t.Errorf("persisted status = %q, want REVOKED", stored.Status)
	}
}

func TestRevokeIdempotent(t *testing.T) {
	reg, _ := newRA(t)
	result, _ := reg.Register(validRequest())
	revReq := &models.RevocationRequest{Reason: models.ReasonCessationOfOperation}
	if _, err := reg.Revoke(result.AgentID, revReq); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if _, err := reg.Revoke(result.AgentID, revReq); err != nil {
		t.Fatalf("second Revoke (idempotent) returned error: %v", err)
	}
}

func TestANSNameTLSealing(t *testing.T) {
	reg, s := newRA(t)
	result, err := reg.Register(validRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries := s.GetTLEntriesByAgentID(result.AgentID)
	if len(entries) != 1 {
		t.Fatalf("expected 1 TL entry after registration, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Event.ANSName != result.ANSName {
		t.Errorf("TL event ANSName = %q, want %q", entry.Event.ANSName, result.ANSName)
	}
	if entry.Event.EventType != models.EventRegistered {
		t.Errorf("TL event type = %q, want AGENT_REGISTERED", entry.Event.EventType)
	}
}

func TestRevokeAddsSecondTLEntry(t *testing.T) {
	reg, s := newRA(t)
	result, _ := reg.Register(validRequest())
	if _, err := reg.Revoke(result.AgentID, &models.RevocationRequest{Reason: models.ReasonSuperseded}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	entries := s.GetTLEntriesByAgentID(result.AgentID)
	if len(entries) != 2 {
		t.Fatalf("expected 2 TL entries (register + revoke), got %d", len(entries))
	}
	if entries[1].Event.EventType != models.EventRevoked {
		t.Errorf("second TL event type = %q, want AGENT_REVOKED", entries[1].Event.EventType)
	}
}

func TestUpdateECH(t *testing.T) {
	reg, s := newRA(t)
	result, _ := reg.Register(validRequest())

	updated, err := reg.UpdateECH(result.AgentID, "AEn+DQBFKwAgACB...")
	if err != nil {
		t.Fatalf("UpdateECH: %v", err)
	}
	if updated.ECHConfigList != "AEn+DQBFKwAgACB..." {
		t.Errorf("ECHConfigList = %q", updated.ECHConfigList)
	}

	// Ensure no TL entry was created.
	entries := s.GetTLEntriesByAgentID(result.AgentID)
	if len(entries) != 1 {
		t.Errorf("expected 1 TL entry after ECH update (no new event), got %d", len(entries))
	}
}

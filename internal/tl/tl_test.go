package tl_test

import (
	"strconv"
	"testing"

	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/store"
	"github.com/ReZorg/ans-registry/internal/tl"
)

func newLog(t *testing.T) (*tl.Log, *store.Store) {
	t.Helper()
	s := store.New()
	l, err := tl.New(s)
	if err != nil {
		t.Fatalf("tl.New: %v", err)
	}
	return l, s
}

func sampleEvent(agentID string) models.TLEventPayload {
	return models.TLEventPayload{
		AnsID:     agentID,
		ANSName:   "ans://v1.0.0.agent.example.com",
		EventType: models.EventRegistered,
		Agent: models.TLAgentInfo{
			Host:       "agent.example.com",
			Name:       "Test Agent",
			Version:    "v1.0.0",
			ProviderID: "PID-abcd",
		},
		Attestations: models.Attestations{
			IdentityCert: models.CertAttestation{
				Fingerprint: "SHA256:aabbcc",
				Type:        "X509-OV-CLIENT",
			},
			ServerCert: models.CertAttestation{
				Fingerprint: "SHA256:ddeeff",
				Type:        "X509-DV-SERVER",
			},
			DomainValidation: "ACME-DNS-01",
		},
		IssuedAt:  "2025-01-01T00:00:00Z",
		ExpiresAt: "2026-01-01T00:00:00Z",
		RAID:      "ra-test",
		Timestamp: "2025-01-01T00:00:00Z",
	}
}

func TestSealEventCreatesEntry(t *testing.T) {
	l, s := newLog(t)
	event := sampleEvent("agent-001")
	entry, err := l.SealEvent("agent-001", event)
	if err != nil {
		t.Fatalf("SealEvent: %v", err)
	}
	if entry.LogID == "" {
		t.Error("expected non-empty LogID")
	}
	if entry.LeafHash == "" {
		t.Error("expected non-empty LeafHash")
	}
	if entry.ProducerSig == "" {
		t.Error("expected non-empty ProducerSig")
	}

	// Verify it was stored.
	stored, err := s.GetTLEntry(entry.LogID)
	if err != nil {
		t.Fatalf("GetTLEntry: %v", err)
	}
	if stored.LogID != entry.LogID {
		t.Errorf("stored LogID = %s, want %s", stored.LogID, entry.LogID)
	}
}

func TestInclusionProofValid(t *testing.T) {
	l, s := newLog(t)

	entry, err := l.SealEvent("probe", sampleEvent("probe"))
	if err != nil {
		t.Fatalf("SealEvent: %v", err)
	}

	stored, err := s.GetTLEntry(entry.LogID)
	if err != nil {
		t.Fatalf("GetTLEntry: %v", err)
	}

	badge, err := l.BuildBadgeResponse(stored, models.StatusActive)
	if err != nil {
		t.Fatalf("BuildBadgeResponse: %v", err)
	}

	if err := tl.VerifyInclusionProof(&badge.InclusionProof); err != nil {
		t.Errorf("VerifyInclusionProof failed: %v", err)
	}
}

func TestCheckpointIssuedAfterSeal(t *testing.T) {
	l, _ := newLog(t)
	if cp := l.LatestCheckpoint(); cp != nil {
		t.Fatal("expected no checkpoint before any seals")
	}

	if _, err := l.SealEvent("a1", sampleEvent("a1")); err != nil {
		t.Fatalf("SealEvent: %v", err)
	}
	cp := l.LatestCheckpoint()
	if cp == nil {
		t.Fatal("expected a checkpoint after sealing an event")
	}
	if cp.TreeSize != 1 {
		t.Errorf("TreeSize = %d, want 1", cp.TreeSize)
	}
	if cp.RootHash == "" {
		t.Error("expected non-empty RootHash")
	}
	if cp.KMSSignature == "" {
		t.Error("expected non-empty KMSSignature")
	}
}

func TestMultipleEventsSequenceNumbers(t *testing.T) {
	l, s := newLog(t)
	for i := range 3 {
		id := "seq-" + strconv.Itoa(i)
		if _, err := l.SealEvent(id, sampleEvent(id)); err != nil {
			t.Fatalf("SealEvent %d: %v", i, err)
		}
	}
	all := s.AllTLEntries()
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	for i, e := range all {
		if e.SequenceNumber != int64(i) {
			t.Errorf("entry %d: SequenceNumber = %d, want %d", i, e.SequenceNumber, i)
		}
	}
}

package store_test

import (
	"strconv"
	"testing"

	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/store"
)

func TestSaveAndGetRegistration(t *testing.T) {
	s := store.New()
	reg := &models.Registration{
		AgentID:  "agent-001",
		ANSName:  "ans://v1.0.0.test.example.com",
		Status:   models.StatusActive,
		Version:  "1.0.0",
		AgentHost: "test.example.com",
	}
	if err := s.SaveRegistration(reg); err != nil {
		t.Fatalf("SaveRegistration: %v", err)
	}
	got, err := s.GetRegistration("agent-001")
	if err != nil {
		t.Fatalf("GetRegistration: %v", err)
	}
	if got.ANSName != reg.ANSName {
		t.Errorf("ANSName = %q, want %q", got.ANSName, reg.ANSName)
	}
}

func TestGetRegistrationNotFound(t *testing.T) {
	s := store.New()
	_, err := s.GetRegistration("no-such-id")
	if err == nil {
		t.Fatal("expected error")
	}
	if err != store.ErrNotFound {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestANSNameConflict(t *testing.T) {
	s := store.New()
	reg1 := &models.Registration{
		AgentID:  "a1",
		ANSName:  "ans://v1.0.0.conflict.example.com",
		Status:   models.StatusActive,
	}
	reg2 := &models.Registration{
		AgentID:  "a2",
		ANSName:  "ans://v1.0.0.conflict.example.com",
		Status:   models.StatusActive,
	}
	if err := s.SaveRegistration(reg1); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := s.SaveRegistration(reg2); err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestANSNameReuseAfterRevocation(t *testing.T) {
	s := store.New()
	reg := &models.Registration{
		AgentID:  "a1",
		ANSName:  "ans://v1.0.0.reuse.example.com",
		Status:   models.StatusRevoked,
	}
	if err := s.SaveRegistration(reg); err != nil {
		t.Fatalf("save revoked: %v", err)
	}
	// Another agent may reuse the same ANSName after revocation.
	reg2 := &models.Registration{
		AgentID:  "a2",
		ANSName:  "ans://v1.0.0.reuse.example.com",
		Status:   models.StatusActive,
	}
	if err := s.SaveRegistration(reg2); err != nil {
		t.Fatalf("save reuse: %v", err)
	}
}

func TestGetRegistrationByANSName(t *testing.T) {
	s := store.New()
	reg := &models.Registration{
		AgentID: "a1",
		ANSName: "ans://v2.0.0.lookup.example.com",
		Status:  models.StatusActive,
	}
	s.SaveRegistration(reg)
	got, err := s.GetRegistrationByANSName("ans://v2.0.0.lookup.example.com")
	if err != nil {
		t.Fatalf("GetRegistrationByANSName: %v", err)
	}
	if got.AgentID != "a1" {
		t.Errorf("AgentID = %q, want a1", got.AgentID)
	}
}

func TestEventStreamPagination(t *testing.T) {
	s := store.New()
	for i := range 5 {
		s.AppendTLEntry(&models.TLEntry{
			LogID:   "log-" + strconv.Itoa(i),
			AgentID: "a1",
			Event:   models.TLEventPayload{},
		})
	}
	page1, cursor := s.EventStreamPage("", "", 3)
	if len(page1) != 3 {
		t.Errorf("page1 len = %d, want 3", len(page1))
	}
	if cursor == "" {
		t.Error("expected non-empty cursor after partial page")
	}
	page2, cursor2 := s.EventStreamPage("", cursor, 3)
	if len(page2) != 2 {
		t.Errorf("page2 len = %d, want 2", len(page2))
	}
	if cursor2 != "" {
		t.Errorf("expected empty cursor at end, got %q", cursor2)
	}
}

func TestCheckpointHistory(t *testing.T) {
	s := store.New()
	for range 5 {
		s.AppendCheckpoint(&models.Checkpoint{TreeSize: 1})
	}
	page, hasMore := s.CheckpointHistory(0, 3)
	if len(page) != 3 {
		t.Errorf("page len = %d, want 3", len(page))
	}
	if !hasMore {
		t.Error("expected hasMore = true")
	}
	page2, hasMore2 := s.CheckpointHistory(3, 3)
	if len(page2) != 2 {
		t.Errorf("page2 len = %d, want 2", len(page2))
	}
	if hasMore2 {
		t.Error("expected hasMore = false on last page")
	}
}

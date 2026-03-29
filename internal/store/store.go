// Package store provides thread-safe in-memory storage for RA and TL records.
package store

import (
	"errors"
	"strings"
	"sync"

	"github.com/ReZorg/ans-registry/internal/models"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrConflict is returned when a duplicate ANSName registration is attempted.
var ErrConflict = errors.New("agent with this ANSName already exists")

// Store holds all persistent state for the registry (RA records, TL entries,
// checkpoints, root keys, and the event stream).
type Store struct {
	mu sync.RWMutex

	// RA state
	registrations map[string]*models.Registration // keyed by agentId
	byANSName     map[string]string               // ansName -> agentId

	// TL state
	tlEntries   []*models.TLEntry            // ordered by sequence number
	tlByLogID   map[string]*models.TLEntry   // logId -> entry
	tlByAgentID map[string][]*models.TLEntry // agentId -> ordered entries
	checkpoints []*models.Checkpoint

	// Root keys
	rootKeys map[string]*models.RootKey // keyId -> key
}

// New creates an empty Store.
func New() *Store {
	return &Store{
		registrations: make(map[string]*models.Registration),
		byANSName:     make(map[string]string),
		tlByLogID:     make(map[string]*models.TLEntry),
		tlByAgentID:   make(map[string][]*models.TLEntry),
		rootKeys:      make(map[string]*models.RootKey),
	}
}

// SaveRegistration creates or updates a registration record.
// On create it enforces uniqueness of ANSName.
func (s *Store) SaveRegistration(r *models.Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.registrations[r.AgentID]
	if !ok {
		// New record — enforce ANSName uniqueness among non-terminal states.
		if id, taken := s.byANSName[r.ANSName]; taken {
			cur := s.registrations[id]
			if cur != nil && cur.Status != models.StatusRevoked && cur.Status != models.StatusExpired {
				return ErrConflict
			}
		}
		s.byANSName[r.ANSName] = r.AgentID
	} else {
		// Update: if ANSName changed (shouldn't happen), keep index consistent.
		if existing.ANSName != r.ANSName {
			delete(s.byANSName, existing.ANSName)
			s.byANSName[r.ANSName] = r.AgentID
		}
	}

	s.registrations[r.AgentID] = r
	return nil
}

// GetRegistration returns the registration identified by agentId.
func (s *Store) GetRegistration(agentID string) (*models.Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.registrations[agentID]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// GetRegistrationByANSName resolves an ANSName to its registration.
func (s *Store) GetRegistrationByANSName(ansName string) (*models.Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byANSName[ansName]
	if !ok {
		return nil, ErrNotFound
	}
	r, ok := s.registrations[id]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// ListRegistrations returns all registrations whose agentHost matches the
// given host (empty string returns all records).
func (s *Store) ListRegistrations(host string) []*models.Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*models.Registration
	for _, r := range s.registrations {
		if host == "" || r.AgentHost == host {
			out = append(out, r)
		}
	}
	return out
}

// AppendTLEntry adds a sealed event to the transparency log.
func (s *Store) AppendTLEntry(e *models.TLEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.SequenceNumber = int64(len(s.tlEntries))
	e.LeafIndex = e.SequenceNumber
	s.tlEntries = append(s.tlEntries, e)
	s.tlByLogID[e.LogID] = e
	s.tlByAgentID[e.AgentID] = append(s.tlByAgentID[e.AgentID], e)
}

// GetTLEntry returns the TL entry identified by logId.
func (s *Store) GetTLEntry(logID string) (*models.TLEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.tlByLogID[logID]
	if !ok {
		return nil, ErrNotFound
	}
	return e, nil
}

// GetTLEntriesByAgentID returns all TL entries for one agent, oldest first.
func (s *Store) GetTLEntriesByAgentID(agentID string) []*models.TLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlByAgentID[agentID]
}

// GetLatestTLEntryByAgentID returns the most recent TL entry for one agent.
func (s *Store) GetLatestTLEntryByAgentID(agentID string) (*models.TLEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := s.tlByAgentID[agentID]
	if len(entries) == 0 {
		return nil, ErrNotFound
	}
	return entries[len(entries)-1], nil
}

// AllTLEntries returns all TL entries ordered by sequence number.
func (s *Store) AllTLEntries() []*models.TLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.TLEntry, len(s.tlEntries))
	copy(out, s.tlEntries)
	return out
}

// TLSize returns the number of sealed entries.
func (s *Store) TLSize() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.tlEntries))
}

// AppendCheckpoint saves a new signed checkpoint.
func (s *Store) AppendCheckpoint(c *models.Checkpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints = append(s.checkpoints, c)
}

// LatestCheckpoint returns the most recent checkpoint, or nil if none exist.
func (s *Store) LatestCheckpoint() *models.Checkpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.checkpoints) == 0 {
		return nil
	}
	return s.checkpoints[len(s.checkpoints)-1]
}

// CheckpointHistory returns checkpoints with cursor-based pagination.
// cursor is the 0-based index of the first result; limit caps the page size.
func (s *Store) CheckpointHistory(cursor, limit int) ([]*models.Checkpoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cursor >= len(s.checkpoints) {
		return nil, false
	}
	end := cursor + limit
	hasMore := end < len(s.checkpoints)
	if end > len(s.checkpoints) {
		end = len(s.checkpoints)
	}
	out := make([]*models.Checkpoint, end-cursor)
	copy(out, s.checkpoints[cursor:end])
	return out, hasMore
}

// SaveRootKey stores or updates a root key.
func (s *Store) SaveRootKey(k *models.RootKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rootKeys[k.KeyID] = k
}

// GetRootKey returns a root key by ID.
func (s *Store) GetRootKey(keyID string) (*models.RootKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.rootKeys[keyID]
	if !ok {
		return nil, ErrNotFound
	}
	return k, nil
}

// ListRootKeys returns all stored root keys.
func (s *Store) ListRootKeys() []*models.RootKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.RootKey, 0, len(s.rootKeys))
	for _, k := range s.rootKeys {
		out = append(out, k)
	}
	return out
}

// EventStreamPage returns a page of TL entries filtered by optional providerID
// and/or after cursor. Entries are ordered by sequence number.
func (s *Store) EventStreamPage(providerID, afterCursor string, limit int) ([]*models.TLEntry, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.TLEntry
	past := afterCursor == ""
	for _, e := range s.tlEntries {
		if !past {
			if e.LogID == afterCursor {
				past = true
			}
			continue
		}
		if providerID != "" && !strings.EqualFold(e.Event.Agent.ProviderID, providerID) {
			continue
		}
		results = append(results, e)
		if len(results) >= limit {
			break
		}
	}

	nextCursor := ""
	if len(results) == limit {
		nextCursor = results[len(results)-1].LogID
	}
	return results, nextCursor
}

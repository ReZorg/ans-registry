// Package api wires up the HTTP handlers for the ANS registry service.
//
// Route table (Go 1.22+ ServeMux syntax):
//
//	POST   /v1/agents                         – register a new agent
//	GET    /v1/agents/{agentId}               – get registration status (RA view)
//	PATCH  /v1/agents/{agentId}/ech           – update ECH config
//	POST   /v1/agents/{agentId}/revoke        – revoke
//	GET    /v1/resolve?ansName=…              – resolve ANSName → registration
//
//	GET    /v1/tl/agents/{agentId}            – TL badge response (with inclusion proof)
//	GET    /v1/tl/agents/{agentId}/audit      – paginated audit history
//	GET    /v1/log/checkpoint                 – latest signed checkpoint
//	GET    /v1/log/checkpoint/history         – checkpoint history
//	GET    /v1/log/schema/{version}           – event schema definition
//	GET    /root-keys                         – TL verification keys
//
//	GET    /v1/events                         – event stream (paginated)
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/ra"
	"github.com/ReZorg/ans-registry/internal/store"
	"github.com/ReZorg/ans-registry/internal/tl"
)

// Handler holds the dependencies shared across all HTTP handlers.
type Handler struct {
	ra    *ra.RA
	tl    *tl.Log
	store *store.Store
}

// New creates a Handler and registers all routes on mux.
func New(mux *http.ServeMux, reg *ra.RA, log *tl.Log, s *store.Store) *Handler {
	h := &Handler{ra: reg, tl: log, store: s}
	h.routes(mux)
	return h
}

func (h *Handler) routes(mux *http.ServeMux) {
	// RA endpoints
	mux.HandleFunc("POST /v1/agents", h.registerAgent)
	mux.HandleFunc("GET /v1/agents/{agentId}", h.getAgent)
	mux.HandleFunc("PATCH /v1/agents/{agentId}/ech", h.updateECH)
	mux.HandleFunc("POST /v1/agents/{agentId}/revoke", h.revokeAgent)
	mux.HandleFunc("GET /v1/resolve", h.resolveANSName)

	// TL endpoints
	mux.HandleFunc("GET /v1/tl/agents/{agentId}", h.tlBadge)
	mux.HandleFunc("GET /v1/tl/agents/{agentId}/audit", h.tlAudit)
	mux.HandleFunc("GET /v1/log/checkpoint", h.latestCheckpoint)
	mux.HandleFunc("GET /v1/log/checkpoint/history", h.checkpointHistory)
	mux.HandleFunc("GET /v1/log/schema/{version}", h.logSchema)
	mux.HandleFunc("GET /root-keys", h.rootKeys)

	// Event stream
	mux.HandleFunc("GET /v1/events", h.events)

	// Health check
	mux.HandleFunc("GET /health", h.health)
}

// --- RA handlers ---

// registerAgent handles POST /v1/agents.
func (h *Handler) registerAgent(w http.ResponseWriter, r *http.Request) {
	var req models.RegistrationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	reg, err := h.ra.Register(&req)
	if err != nil {
		var ve *ra.ValidationError
		var ce *ra.ConflictError
		switch {
		case errors.As(err, &ve):
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.As(err, &ce):
			writeError(w, http.StatusConflict, "CONFLICT", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusCreated, reg)
}

// getAgent handles GET /v1/agents/{agentId}.
func (h *Handler) getAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentId")
	reg, err := h.store.GetRegistration(agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reg)
}

// updateECH handles PATCH /v1/agents/{agentId}/ech.
func (h *Handler) updateECH(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentId")
	var req models.ECHUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if strings.TrimSpace(req.ECHConfigList) == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "echConfigList is required")
		return
	}

	reg, err := h.ra.UpdateECH(agentID, req.ECHConfigList)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
			return
		}
		var ve *ra.ValidationError
		if errors.As(err, &ve) {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reg)
}

// revokeAgent handles POST /v1/agents/{agentId}/revoke.
func (h *Handler) revokeAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentId")
	var req models.RevocationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.Reason == "" {
		req.Reason = models.ReasonUnspecified
	}
	if req.Comments != "" && len(req.Comments) > 200 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "comments must not exceed 200 characters")
		return
	}

	resp, err := h.ra.Revoke(agentID, &req)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
			return
		}
		var ve *ra.ValidationError
		if errors.As(err, &ve) {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// resolveANSName handles GET /v1/resolve?ansName=ans://...
func (h *Handler) resolveANSName(w http.ResponseWriter, r *http.Request) {
	ansName := r.URL.Query().Get("ansName")
	if ansName == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ansName query parameter is required")
		return
	}
	reg, err := h.store.GetRegistrationByANSName(ansName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "ANSName not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reg)
}

// --- TL handlers ---

// tlBadge handles GET /v1/tl/agents/{agentId}.
func (h *Handler) tlBadge(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentId")

	reg, err := h.store.GetRegistration(agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	entry, err := h.store.GetLatestTLEntryByAgentID(agentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "no TL entry found for agent")
		return
	}

	badge, err := h.tl.BuildBadgeResponse(entry, reg.Status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, badge)
}

// tlAudit handles GET /v1/tl/agents/{agentId}/audit.
func (h *Handler) tlAudit(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentId")
	if _, err := h.store.GetRegistration(agentID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	entries := h.store.GetTLEntriesByAgentID(agentID)
	type auditItem struct {
		LogID          string             `json:"logId"`
		SequenceNumber int64              `json:"sequenceNumber"`
		SchemaVersion  string             `json:"schemaVersion"`
		Event          models.TLEventPayload `json:"event"`
		CreatedAt      time.Time          `json:"createdAt"`
	}
	items := make([]auditItem, len(entries))
	for i, e := range entries {
		items[i] = auditItem{
			LogID:          e.LogID,
			SequenceNumber: e.SequenceNumber,
			SchemaVersion:  e.SchemaVersion,
			Event:          e.Event,
			CreatedAt:      e.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agentId": agentID,
		"total":   len(items),
		"events":  items,
	})
}

// latestCheckpoint handles GET /v1/log/checkpoint.
func (h *Handler) latestCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp := h.tl.LatestCheckpoint()
	if cp == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"treeSize":  0,
			"rootHash":  "",
			"timestamp": time.Now().UTC(),
		})
		return
	}
	writeJSON(w, http.StatusOK, cp)
}

// checkpointHistory handles GET /v1/log/checkpoint/history.
func (h *Handler) checkpointHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cursor, _ := strconv.Atoi(q.Get("cursor"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	cps, hasMore := h.store.CheckpointHistory(cursor, limit)
	nextCursor := ""
	if hasMore {
		nextCursor = strconv.Itoa(cursor + limit)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"checkpoints": cps,
		"nextCursor":  nextCursor,
		"hasMore":     hasMore,
	})
}

// logSchema handles GET /v1/log/schema/{version}.
func (h *Handler) logSchema(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	switch strings.ToUpper(version) {
	case "V1":
		writeJSON(w, http.StatusOK, schemaV1)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "schema version not found: "+version)
	}
}

// rootKeys handles GET /root-keys.
func (h *Handler) rootKeys(w http.ResponseWriter, r *http.Request) {
	keys := h.store.ListRootKeys()
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// events handles GET /v1/events.
func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	providerID := q.Get("providerId")
	after := q.Get("after")
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	entries, nextCursor := h.store.EventStreamPage(providerID, after, limit)
	items := make([]models.EventStreamItem, len(entries))
	for i, e := range entries {
		items[i] = models.EventStreamItem{
			LogID:         e.LogID,
			SchemaVersion: e.SchemaVersion,
			Payload:       e.Event,
			TLSignature:   e.TLSignature,
			CreatedAt:     e.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":     items,
		"nextCursor": nextCursor,
		"hasMore":    nextCursor != "",
	})
}

// health handles GET /health.
func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Helpers ---

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, models.ErrorResponse{Code: code, Message: msg})
}

// schemaV1 is the JSON Schema for V1 TL events, returned by GET /v1/log/schema/V1.
var schemaV1 = map[string]any{
	"$schema":     "https://json-schema.org/draft/2020-12/schema",
	"$id":         "https://ans.example/schemas/tl-event-v1.json",
	"title":       "ANS Transparency Log Event V1",
	"description": "Schema for events sealed into the ANS Transparency Log.",
	"type":        "object",
	"required":    []string{"ansId", "ansName", "eventType", "agent", "attestations", "issuedAt", "raId", "timestamp"},
	"properties": map[string]any{
		"ansId":     map[string]string{"type": "string", "format": "uuid"},
		"ansName":   map[string]string{"type": "string", "pattern": `^ans://v\d+\.\d+\.\d+\..+$`},
		"eventType": map[string]any{"type": "string", "enum": []string{"AGENT_REGISTERED", "AGENT_RENEWED", "AGENT_REVOKED", "AGENT_DEPRECATED"}},
		"agent": map[string]any{
			"type":     "object",
			"required": []string{"host", "name", "version", "providerId"},
			"properties": map[string]any{
				"host":       map[string]string{"type": "string"},
				"name":       map[string]string{"type": "string"},
				"version":    map[string]string{"type": "string"},
				"providerId": map[string]string{"type": "string"},
				"lei":        map[string]string{"type": "string"},
			},
		},
		"attestations": map[string]any{
			"type":     "object",
			"required": []string{"identityCert", "serverCert", "dnsRecordsProvisioned", "domainValidation"},
		},
		"expiresAt":            map[string]string{"type": "string", "format": "date-time"},
		"issuedAt":             map[string]string{"type": "string", "format": "date-time"},
		"raId":                 map[string]string{"type": "string"},
		"timestamp":            map[string]string{"type": "string", "format": "date-time"},
		"revocationReasonCode": map[string]string{"type": "string"},
		"revokedAt":            map[string]string{"type": "string", "format": "date-time"},
	},
}

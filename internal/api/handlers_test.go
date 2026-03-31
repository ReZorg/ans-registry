package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ReZorg/ans-registry/internal/api"
	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/ra"
	"github.com/ReZorg/ans-registry/internal/store"
	"github.com/ReZorg/ans-registry/internal/tl"
)

func newServer(t *testing.T) *httptest.Server {
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
	mux := http.NewServeMux()
	api.New(mux, reg, l, s)
	return httptest.NewServer(mux)
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func getJSON(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func decodeBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return v
}

func validRegPayload() models.RegistrationRequest {
	return models.RegistrationRequest{
		AgentDisplayName: "API Test Agent",
		Version:          "2.0.0",
		AgentHost:        "api-test.example.com",
		Endpoints: []models.Endpoint{
			{
				Protocol: models.ProtocolA2A,
				AgentURL: "https://api-test.example.com/a2a",
			},
		},
		IdentityCSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBTest\n-----END CERTIFICATE REQUEST-----",
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := getJSON(t, srv, "/health")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d, want 200", resp.StatusCode)
	}
}

func TestRegisterAndGetAgent(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	// Register.
	resp := postJSON(t, srv, "/v1/agents", validRegPayload())
	if resp.StatusCode != http.StatusCreated {
		body := decodeBody[map[string]any](t, resp)
		t.Fatalf("POST /v1/agents status = %d, body = %v", resp.StatusCode, body)
	}
	var reg models.Registration
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	if reg.AgentID == "" {
		t.Fatal("expected agentId")
	}

	// Get by agentId.
	getResp := getJSON(t, srv, "/v1/agents/"+reg.AgentID)
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/agents/%s status = %d, want 200", reg.AgentID, getResp.StatusCode)
	}
	stored := decodeBody[models.Registration](t, getResp)
	if stored.ANSName != reg.ANSName {
		t.Errorf("ANSName = %q, want %q", stored.ANSName, reg.ANSName)
	}
}

func TestRegisterConflict(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	payload := validRegPayload()
	postJSON(t, srv, "/v1/agents", payload)
	resp2 := postJSON(t, srv, "/v1/agents", payload)
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate registration status = %d, want 409", resp2.StatusCode)
	}
}

func TestRegisterValidationError(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	payload := validRegPayload()
	payload.Version = "not-semver"
	resp := postJSON(t, srv, "/v1/agents", payload)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid version status = %d, want 400", resp.StatusCode)
	}
	errBody := decodeBody[models.ErrorResponse](t, resp)
	if errBody.Code != "VALIDATION_ERROR" {
		t.Errorf("error code = %q, want VALIDATION_ERROR", errBody.Code)
	}
}

func TestResolveANSName(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	payload := validRegPayload()
	resp := postJSON(t, srv, "/v1/agents", payload)
	var reg models.Registration
	json.NewDecoder(resp.Body).Decode(&reg)

	resolveResp := getJSON(t, srv, "/v1/resolve?ansName="+reg.ANSName)
	if resolveResp.StatusCode != http.StatusOK {
		t.Errorf("resolve status = %d, want 200", resolveResp.StatusCode)
	}
	resolved := decodeBody[models.Registration](t, resolveResp)
	if resolved.AgentID != reg.AgentID {
		t.Errorf("resolved agentId = %q, want %q", resolved.AgentID, reg.AgentID)
	}
}

func TestResolveNotFound(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	resp := getJSON(t, srv, "/v1/resolve?ansName=ans://v9.9.9.nope.example.com")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("resolve missing status = %d, want 404", resp.StatusCode)
	}
}

func TestRevokeAgent(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := postJSON(t, srv, "/v1/agents", validRegPayload())
	var reg models.Registration
	json.NewDecoder(resp.Body).Decode(&reg)

	revokeResp := postJSON(t, srv, "/v1/agents/"+reg.AgentID+"/revoke", models.RevocationRequest{
		Reason: models.ReasonCessationOfOperation,
	})
	if revokeResp.StatusCode != http.StatusOK {
		body := decodeBody[map[string]any](t, revokeResp)
		t.Fatalf("revoke status = %d, body = %v", revokeResp.StatusCode, body)
	}
	revResp := decodeBody[models.RevocationResponse](t, revokeResp)
	if revResp.Status != models.StatusRevoked {
		t.Errorf("revoke status = %q, want REVOKED", revResp.Status)
	}
}

func TestTLBadge(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := postJSON(t, srv, "/v1/agents", validRegPayload())
	var reg models.Registration
	json.NewDecoder(resp.Body).Decode(&reg)

	badgeResp := getJSON(t, srv, "/v1/tl/agents/"+reg.AgentID)
	if badgeResp.StatusCode != http.StatusOK {
		body := decodeBody[map[string]any](t, badgeResp)
		t.Fatalf("TL badge status = %d, body = %v", badgeResp.StatusCode, body)
	}

	var badge models.TLBadgeResponse
	if err := json.NewDecoder(badgeResp.Body).Decode(&badge); err != nil {
		t.Fatalf("decode badge: %v", err)
	}
	if badge.SchemaVersion != "V1" {
		t.Errorf("schemaVersion = %q, want V1", badge.SchemaVersion)
	}
	if badge.Status != models.StatusActive {
		t.Errorf("badge status = %q, want ACTIVE", badge.Status)
	}
	if badge.InclusionProof.RootHash == "" {
		t.Error("expected non-empty RootHash in inclusion proof")
	}
}

func TestTLAudit(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := postJSON(t, srv, "/v1/agents", validRegPayload())
	var reg models.Registration
	json.NewDecoder(resp.Body).Decode(&reg)

	// Revoke to get a second event.
	postJSON(t, srv, "/v1/agents/"+reg.AgentID+"/revoke", models.RevocationRequest{
		Reason: models.ReasonSuperseded,
	})

	auditResp := getJSON(t, srv, "/v1/tl/agents/"+reg.AgentID+"/audit")
	if auditResp.StatusCode != http.StatusOK {
		t.Fatalf("audit status = %d", auditResp.StatusCode)
	}
	body := decodeBody[map[string]any](t, auditResp)
	events, _ := body["events"].([]any)
	if len(events) != 2 {
		t.Errorf("expected 2 audit events, got %d", len(events))
	}
}

func TestCheckpoint(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	// Seal an event so a checkpoint exists.
	postJSON(t, srv, "/v1/agents", validRegPayload())

	resp := getJSON(t, srv, "/v1/log/checkpoint")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("checkpoint status = %d, want 200", resp.StatusCode)
	}
	cp := decodeBody[models.Checkpoint](t, resp)
	if cp.TreeSize < 1 {
		t.Errorf("treeSize = %d, want >= 1", cp.TreeSize)
	}
}

func TestLogSchema(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := getJSON(t, srv, "/v1/log/schema/V1")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("schema status = %d, want 200", resp.StatusCode)
	}

	resp404 := getJSON(t, srv, "/v1/log/schema/V99")
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("unknown schema status = %d, want 404", resp404.StatusCode)
	}
}

func TestRootKeys(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := getJSON(t, srv, "/root-keys")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("root-keys status = %d, want 200", resp.StatusCode)
	}
	body := decodeBody[map[string]any](t, resp)
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Error("expected at least one root key")
	}
}

func TestEventStream(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	// Register two agents to create two events.
	p1 := validRegPayload()
	p2 := validRegPayload()
	p2.AgentHost = "second.example.com"
	p2.Version = "1.0.0"
	postJSON(t, srv, "/v1/agents", p1)
	postJSON(t, srv, "/v1/agents", p2)

	resp := getJSON(t, srv, "/v1/events?limit=10")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", resp.StatusCode)
	}
	body := decodeBody[map[string]any](t, resp)
	events, _ := body["events"].([]any)
	if len(events) < 2 {
		t.Errorf("expected >= 2 events, got %d", len(events))
	}
}

func TestGetAgentNotFound(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	resp := getJSON(t, srv, "/v1/agents/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

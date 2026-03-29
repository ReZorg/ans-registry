// Package models defines the core data structures for the ANS registry.
package models

import "time"

// AgentStatus represents the lifecycle state of a registered agent.
type AgentStatus string

const (
	StatusPending    AgentStatus = "PENDING"
	StatusPendingDNS AgentStatus = "PENDING_DNS"
	StatusActive     AgentStatus = "ACTIVE"
	StatusDeprecated AgentStatus = "DEPRECATED"
	StatusRevoked    AgentStatus = "REVOKED"
	StatusExpired    AgentStatus = "EXPIRED"
)

// EventType labels each transparency log entry.
type EventType string

const (
	EventRegistered EventType = "AGENT_REGISTERED"
	EventRenewed    EventType = "AGENT_RENEWED"
	EventRevoked    EventType = "AGENT_REVOKED"
	EventDeprecated EventType = "AGENT_DEPRECATED"
)

// Protocol identifies the communication protocol of an agent endpoint.
type Protocol string

const (
	ProtocolA2A     Protocol = "A2A"
	ProtocolMCP     Protocol = "MCP"
	ProtocolHTTPAPI Protocol = "HTTP-API"
)

// RevocationReason enumerates RFC 5280 reason codes used in revocation requests.
type RevocationReason string

const (
	ReasonUnspecified          RevocationReason = "UNSPECIFIED"
	ReasonKeyCompromise        RevocationReason = "KEY_COMPROMISE"
	ReasonAffiliationChanged   RevocationReason = "AFFILIATION_CHANGED"
	ReasonSuperseded           RevocationReason = "SUPERSEDED"
	ReasonCessationOfOperation RevocationReason = "CESSATION_OF_OPERATION"
)

// Function describes a single callable capability exposed by an endpoint.
type Function struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// Endpoint describes one protocol-specific entry point of an agent.
type Endpoint struct {
	Protocol         Protocol   `json:"protocol"`
	AgentURL         string     `json:"agentUrl"`
	MetadataURL      string     `json:"metadataUrl,omitempty"`
	DocumentationURL string     `json:"documentationUrl,omitempty"`
	Transports       []string   `json:"transports,omitempty"`
	Functions        []Function `json:"functions,omitempty"`
}

// VerifiableClaim is a third-party attestation attached to an ANS Agent Card.
type VerifiableClaim struct {
	Type      string `json:"type"`
	Issuer    string `json:"issuer"`
	Hash      string `json:"hash"`
	URL       string `json:"url"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// ANSAgentCard is the metadata document hosted by the AHP at agent_card_url.
type ANSAgentCard struct {
	ANSName          string            `json:"ansName"`
	AgentDisplayName string            `json:"agentDisplayName"`
	AgentDescription string            `json:"agentDescription,omitempty"`
	Version          string            `json:"version"`
	AgentHost        string            `json:"agentHost"`
	ReleaseChannel   string            `json:"releaseChannel,omitempty"`
	Endpoints        []Endpoint        `json:"endpoints"`
	VerifiableClaims []VerifiableClaim `json:"verifiableClaims,omitempty"`
}

// RegistrationRequest is the payload the AHP submits to POST /v1/agents.
type RegistrationRequest struct {
	AgentDisplayName string        `json:"agentDisplayName"`
	AgentDescription string        `json:"agentDescription,omitempty"`
	Version          string        `json:"version"`
	AgentHost        string        `json:"agentHost"`
	Endpoints        []Endpoint    `json:"endpoints"`
	IdentityCSRPEM   string        `json:"identityCsrPEM"`
	ServerCSRPEM     string        `json:"serverCsrPEM,omitempty"`
	ServerCertPEM    string        `json:"serverCertificatePEM,omitempty"`
	AgentCardContent *ANSAgentCard `json:"agentCardContent,omitempty"`
	OnChainID        string        `json:"onChainId,omitempty"`
	ENSName          string        `json:"ensName,omitempty"`
	LEI              string        `json:"lei,omitempty"`
	ECHConfigList    string        `json:"echConfigList,omitempty"`
}

// Registration is the RA's internal record for one agent version.
type Registration struct {
	AgentID          string        `json:"agentId"`
	ANSName          string        `json:"ansName"`
	AgentDisplayName string        `json:"agentDisplayName"`
	AgentDescription string        `json:"agentDescription,omitempty"`
	Version          string        `json:"version"`
	AgentHost        string        `json:"agentHost"`
	Endpoints        []Endpoint    `json:"endpoints"`
	IdentityCertPEM  string        `json:"identityCertPEM,omitempty"`
	ServerCertPEM    string        `json:"serverCertPEM,omitempty"`
	Status           AgentStatus   `json:"status"`
	ProviderID       string        `json:"providerId"`
	LEI              string        `json:"lei,omitempty"`
	RAID             string        `json:"raId"`
	AgentCardContent *ANSAgentCard `json:"agentCardContent,omitempty"`
	AgentCardHash    string        `json:"agentCardHash,omitempty"`
	ECHConfigList    string        `json:"echConfigList,omitempty"`
	IssuedAt         time.Time     `json:"issuedAt"`
	ExpiresAt        time.Time     `json:"expiresAt"`
	SupersedesID     string        `json:"supersedesId,omitempty"`
	LogEntryID       string        `json:"logEntryId,omitempty"`
	DNSRecords       *DNSRecordSet `json:"dnsRecords,omitempty"`
}

// DNSRecordSet contains the DNS record content generated by the RA.
type DNSRecordSet struct {
	ANS      []string `json:"_ans"`
	ANSBadge string   `json:"_ans-badge"`
	HTTPS    string   `json:"https,omitempty"`
	TLSA     string   `json:"_443._tcp,omitempty"`
}

// CertAttestation captures the certificate fingerprints sealed into the TL.
type CertAttestation struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
}

// Attestations groups the certificate and DNS attestations in a TL event.
type Attestations struct {
	IdentityCert        CertAttestation `json:"identityCert"`
	ServerCert          CertAttestation `json:"serverCert"`
	DNSRecordsProvisioned DNSRecordSet  `json:"dnsRecordsProvisioned"`
	DomainValidation    string          `json:"domainValidation"`
}

// TLEventPayload is the RA-authored event submitted to the Transparency Log.
type TLEventPayload struct {
	AnsID        string          `json:"ansId"`
	ANSName      string          `json:"ansName"`
	EventType    EventType       `json:"eventType"`
	Agent        TLAgentInfo     `json:"agent"`
	Attestations Attestations    `json:"attestations"`
	ExpiresAt    string          `json:"expiresAt"`
	IssuedAt     string          `json:"issuedAt"`
	RAID         string          `json:"raId"`
	Timestamp    string          `json:"timestamp"`

	// Revocation-only fields
	RevocationReasonCode RevocationReason `json:"revocationReasonCode,omitempty"`
	RevokedAt            string           `json:"revokedAt,omitempty"`
}

// TLAgentInfo is the agent sub-object within a TL event.
type TLAgentInfo struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	ProviderID string `json:"providerId"`
	LEI        string `json:"lei,omitempty"`
}

// ProducerEnvelope wraps the RA-signed event inside the TL entry.
type ProducerEnvelope struct {
	Event     TLEventPayload `json:"event"`
	KeyID     string         `json:"keyId"`
	Signature string         `json:"signature"`
}

// InclusionProof proves that an event exists at a specific position in the log.
type InclusionProof struct {
	LeafHash      string   `json:"leafHash"`
	LeafIndex     int64    `json:"leafIndex"`
	TreeSize      int64    `json:"treeSize"`
	TreeVersion   int      `json:"treeVersion"`
	Path          []string `json:"path"`
	RootHash      string   `json:"rootHash"`
	RootSignature string   `json:"rootSignature"`
}

// TLBadgeResponse is returned by GET /v1/agents/{agentId} on the TL.
type TLBadgeResponse struct {
	SchemaVersion  string    `json:"schemaVersion"`
	Status         AgentStatus `json:"status"`
	Payload        struct {
		LogID    string           `json:"logId"`
		Producer ProducerEnvelope `json:"producer"`
	} `json:"payload"`
	Signature      string         `json:"signature"`
	InclusionProof InclusionProof `json:"inclusionProof"`
}

// TLEntry is the internal TL record for a single sealed event.
type TLEntry struct {
	LogID          string         `json:"logId"`
	SequenceNumber int64          `json:"sequenceNumber"`
	LeafIndex      int64          `json:"leafIndex"`
	LeafHash       string         `json:"leafHash"`
	AgentID        string         `json:"agentId"`
	Event          TLEventPayload `json:"event"`
	ProducerKeyID  string         `json:"producerKeyId"`
	ProducerSig    string         `json:"producerSignature"`
	TLSignature    string         `json:"tlSignature"`
	SchemaVersion  string         `json:"schemaVersion"`
	CreatedAt      time.Time      `json:"createdAt"`
}

// Checkpoint is a signed snapshot of the TL's root hash.
type Checkpoint struct {
	TreeSize      int64     `json:"treeSize"`
	RootHash      string    `json:"rootHash"`
	KMSSignature  string    `json:"kmsSignature"`
	TreeVersion   int       `json:"treeVersion"`
	Timestamp     time.Time `json:"timestamp"`
}

// RootKey is a public key registered with the TL for signature verification.
type RootKey struct {
	KeyID       string    `json:"keyId"`
	PublicKeyPEM string   `json:"publicKeyPEM"`
	Algorithm   string    `json:"algorithm"`
	ValidFrom   time.Time `json:"validFrom"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	IsActive    bool      `json:"isActive"`
}

// RevocationRequest is the payload for POST /v1/agents/{agentId}/revoke.
type RevocationRequest struct {
	Reason   RevocationReason `json:"reason"`
	Comments string           `json:"comments,omitempty"`
}

// RevocationResponse is returned after a successful revocation.
type RevocationResponse struct {
	AgentID          string           `json:"agentId"`
	ANSName          string           `json:"ansName"`
	Status           AgentStatus      `json:"status"`
	Reason           RevocationReason `json:"reason"`
	RevokedAt        time.Time        `json:"revokedAt"`
	DNSRecordsToRemove []DNSRecord    `json:"dnsRecordsToRemove,omitempty"`
}

// DNSRecord represents a single DNS record to be provisioned or removed.
type DNSRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
}

// EventStreamItem is one entry in the GET /v1/events response.
type EventStreamItem struct {
	LogID         string         `json:"logId"`
	SchemaVersion string         `json:"schemaVersion"`
	Payload       TLEventPayload `json:"payload"`
	TLSignature   string         `json:"tlSignature"`
	CreatedAt     time.Time      `json:"createdAt"`
}

// ECHUpdateRequest is the payload for PATCH /v1/agents/{agentId}/ech.
type ECHUpdateRequest struct {
	ECHConfigList string `json:"echConfigList"`
}

// ErrorResponse is the standard error body returned by the API.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

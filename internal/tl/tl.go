// Package tl implements the ANS Transparency Log.
//
// The log uses a binary Merkle hash tree. Each leaf stores the SHA-256 hash of
// a canonicalized TL event. The root hash, signed by the KMS key, constitutes
// a Signed Tree Head (checkpoint). Inclusion proofs let any client verify that
// a specific entry is present at a given position without trusting the server.
package tl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ReZorg/ans-registry/internal/models"
	"github.com/ReZorg/ans-registry/internal/store"
)

// Log is the Transparency Log service.
type Log struct {
	store      *store.Store
	kmsKey     *ecdsa.PrivateKey
	kmsKeyID   string
	raKey      *ecdsa.PrivateKey
	raKeyID    string
	treeVersion int
}

// New creates a new Log, generating ephemeral KMS and RA signing keys.
func New(s *store.Store) (*Log, error) {
	kmsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate KMS key: %w", err)
	}
	raKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate RA key: %w", err)
	}

	kmsKeyID := "kms-root-key-" + uuid.New().String()
	raKeyID := "ra-key-" + uuid.New().String()

	// Publish the RA's public key so external verifiers can check producer sigs.
	pubDER, err := x509.MarshalPKIXPublicKey(&raKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal RA public key: %w", err)
	}
	raPubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// Publish the KMS public key for root-key endpoint.
	kmsDER, err := x509.MarshalPKIXPublicKey(&kmsKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal KMS public key: %w", err)
	}
	kmsPubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: kmsDER}))

	now := time.Now().UTC()
	s.SaveRootKey(&models.RootKey{
		KeyID:        kmsKeyID,
		PublicKeyPEM: kmsPubPEM,
		Algorithm:    "ES256",
		ValidFrom:    now,
		IsActive:     true,
	})
	s.SaveRootKey(&models.RootKey{
		KeyID:        raKeyID,
		PublicKeyPEM: raPubPEM,
		Algorithm:    "ES256",
		ValidFrom:    now,
		IsActive:     true,
	})

	return &Log{
		store:       s,
		kmsKey:      kmsKey,
		kmsKeyID:    kmsKeyID,
		raKey:       raKey,
		raKeyID:     raKeyID,
		treeVersion: 1,
	}, nil
}

// RAKeyID returns the key identifier for the RA signing key.
func (l *Log) RAKeyID() string { return l.raKeyID }

// SealEvent signs the event with the RA key, appends it to the log, then
// issues a new checkpoint. It returns the resulting TL entry.
func (l *Log) SealEvent(agentID string, event models.TLEventPayload) (*models.TLEntry, error) {
	logID := uuid.New().String()

	// Canonicalize and hash the event payload.
	eventBytes, err := canonicalize(event)
	if err != nil {
		return nil, fmt.Errorf("canonicalize event: %w", err)
	}
	leafHash := hashBytes(eventBytes)

	// Sign with RA key (producer signature).
	producerSig, err := sign(l.raKey, l.raKeyID, leafHash)
	if err != nil {
		return nil, fmt.Errorf("producer signature: %w", err)
	}

	// Compute the TL's own signature over the full entry.
	entryBytes := []byte(logID + leafHash)
	tlSig, err := sign(l.kmsKey, l.kmsKeyID, string(hashBytes(entryBytes)))
	if err != nil {
		return nil, fmt.Errorf("TL signature: %w", err)
	}

	entry := &models.TLEntry{
		LogID:         logID,
		LeafHash:      leafHash,
		AgentID:       agentID,
		Event:         event,
		ProducerKeyID: l.raKeyID,
		ProducerSig:   producerSig,
		TLSignature:   tlSig,
		SchemaVersion: "V1",
		CreatedAt:     time.Now().UTC(),
	}

	l.store.AppendTLEntry(entry)
	l.issueCheckpoint()

	return entry, nil
}

// BuildBadgeResponse constructs the TL badge response for GET /v1/agents/{agentId}.
func (l *Log) BuildBadgeResponse(entry *models.TLEntry, status models.AgentStatus) (*models.TLBadgeResponse, error) {
	proof, err := l.buildInclusionProof(entry)
	if err != nil {
		return nil, fmt.Errorf("build inclusion proof: %w", err)
	}

	resp := &models.TLBadgeResponse{
		SchemaVersion: "V1",
		Status:        status,
		Signature:     entry.TLSignature,
		InclusionProof: *proof,
	}
	resp.Payload.LogID = entry.LogID
	resp.Payload.Producer = models.ProducerEnvelope{
		Event:     entry.Event,
		KeyID:     entry.ProducerKeyID,
		Signature: entry.ProducerSig,
	}
	return resp, nil
}

// LatestCheckpoint returns the most recent signed checkpoint.
func (l *Log) LatestCheckpoint() *models.Checkpoint {
	return l.store.LatestCheckpoint()
}

// issueCheckpoint builds a new Merkle root over all current entries and signs it.
func (l *Log) issueCheckpoint() {
	entries := l.store.AllTLEntries()
	hashes := make([]string, len(entries))
	for i, e := range entries {
		hashes[i] = e.LeafHash
	}
	root := merkleRoot(hashes)

	rootSig, err := sign(l.kmsKey, l.kmsKeyID, root)
	if err != nil {
		// Non-fatal: the entry is already in the log. Log the error and continue.
		return
	}

	l.store.AppendCheckpoint(&models.Checkpoint{
		TreeSize:    int64(len(entries)),
		RootHash:    root,
		KMSSignature: rootSig,
		TreeVersion: l.treeVersion,
		Timestamp:   time.Now().UTC(),
	})
}

// buildInclusionProof builds a Merkle inclusion proof for the given entry.
func (l *Log) buildInclusionProof(entry *models.TLEntry) (*models.InclusionProof, error) {
	entries := l.store.AllTLEntries()
	n := int64(len(entries))
	if entry.LeafIndex >= n {
		return nil, fmt.Errorf("leaf index %d out of range (tree size %d)", entry.LeafIndex, n)
	}

	hashes := make([]string, n)
	for i, e := range entries {
		hashes[i] = e.LeafHash
	}

	path := merkleProofPath(hashes, int(entry.LeafIndex))
	root := merkleRoot(hashes)

	rootSig, err := sign(l.kmsKey, l.kmsKeyID, root)
	if err != nil {
		return nil, fmt.Errorf("sign root: %w", err)
	}

	return &models.InclusionProof{
		LeafHash:      entry.LeafHash,
		LeafIndex:     entry.LeafIndex,
		TreeSize:      n,
		TreeVersion:   l.treeVersion,
		Path:          path,
		RootHash:      root,
		RootSignature: rootSig,
	}, nil
}

// VerifyInclusionProof verifies that leafHash at leafIndex is included in the
// tree represented by rootHash. It returns nil on success.
func VerifyInclusionProof(proof *models.InclusionProof) error {
	computed := computeRoot(proof.LeafHash, int(proof.LeafIndex), int(proof.TreeSize), proof.Path)
	if computed != proof.RootHash {
		return fmt.Errorf("inclusion proof invalid: computed root %s != claimed root %s", computed, proof.RootHash)
	}
	return nil
}

// --- Merkle tree helpers ---

// merkleRoot computes the root hash of a list of leaf hashes using a
// balanced binary tree (RFC 6962 §2.1 algorithm).
func merkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return hex.EncodeToString(sha256.New().Sum(nil))
	}
	return buildTree(leaves)
}

func buildTree(leaves []string) string {
	if len(leaves) == 1 {
		return leaves[0]
	}
	mid := len(leaves) / 2
	left := buildTree(leaves[:mid])
	right := buildTree(leaves[mid:])
	return nodeHash(left, right)
}

func nodeHash(left, right string) string {
	h := sha256.New()
	h.Write([]byte{0x01}) // node prefix per RFC 6962
	h.Write([]byte(left + right))
	return hex.EncodeToString(h.Sum(nil))
}

// merkleProofPath returns the sibling hashes needed to prove inclusion of the
// leaf at index idx in the tree defined by leaves.
func merkleProofPath(leaves []string, idx int) []string {
	var path []string
	buildProofPath(leaves, idx, &path)
	return path
}

func buildProofPath(leaves []string, idx int, path *[]string) {
	if len(leaves) <= 1 {
		return
	}
	mid := len(leaves) / 2
	if idx < mid {
		sibling := buildTree(leaves[mid:])
		*path = append(*path, sibling)
		buildProofPath(leaves[:mid], idx, path)
	} else {
		sibling := buildTree(leaves[:mid])
		*path = append(*path, sibling)
		buildProofPath(leaves[mid:], idx-mid, path)
	}
}

// computeRoot reconstructs the Merkle root from a proof path.
func computeRoot(leafHash string, idx, treeSize int, path []string) string {
	h := leafHash
	for _, sibling := range path {
		mid := treeSize / 2
		if idx < mid {
			h = nodeHash(h, sibling)
		} else {
			h = nodeHash(sibling, h)
		}
		treeSize = (treeSize + 1) / 2
	}
	return h
}

// --- Cryptographic helpers ---

// hashBytes returns the hex-encoded SHA-256 hash of the input.
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// canonicalize JSON-encodes v deterministically (field order as struct tags).
func canonicalize(v any) ([]byte, error) {
	return json.Marshal(v)
}

// sign produces a compact JWS-style base64url signature over the message hash.
func sign(key *ecdsa.PrivateKey, keyID, message string) (string, error) {
	hash := sha256.Sum256([]byte(message))
	sig, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	// Encode as "base64(header).base64(sig)" mimicking compact JWS structure.
	header := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"alg":"ES256","kid":"%s","typ":"JWS"}`, keyID),
	))
	body := base64.RawURLEncoding.EncodeToString(sig)
	return header + ".." + body, nil
}

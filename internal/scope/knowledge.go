package scope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	knowledgev1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/knowledge/v1"
)

// SearchRequest is what the trusted harness may ask the Knowledge expert
// relay (P2.4, the team's Retrieval specialist): a snapshot, a query and
// the bounds. The subject (tenant, project, actor) is the operation's as
// Control records it, never the caller's word; Knowledge decides
// readability for that actor and asks Control's commercial authorization.
type SearchRequest struct {
	SnapshotID         string `json:"snapshotId"`
	Query              string `json:"query"`
	MaxContextItems    uint32 `json:"maxContextItems"`
	RetrievalProfileID string `json:"retrievalProfileId"`
	Deadline           string `json:"deadline,omitempty"`
}

// ParseSearchRequest decodes the caller's bytes strictly.
func ParseSearchRequest(raw []byte) (SearchRequest, error) {
	var r SearchRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return SearchRequest{}, err
	}
	if dec.More() {
		return SearchRequest{}, errors.New("trailing data")
	}
	if r.SnapshotID == "" || r.Query == "" || r.RetrievalProfileID == "" || r.MaxContextItems < 1 || r.MaxContextItems > 64 {
		return SearchRequest{}, errors.New("snapshotId, query, retrievalProfileId and maxContextItems (1..64) are required")
	}
	return r, nil
}

// BindSearch builds Knowledge's SearchRequest under the confirmed scope;
// the deadline is the attempt's unless the caller asked for an earlier one.
func BindSearch(s *Scope, r SearchRequest) (*knowledgev1.SearchRequest, error) {
	if s.ActorID == "" {
		return nil, errors.New("the operation names no actor")
	}
	deadline := s.Deadline
	if r.Deadline != "" {
		requested, err := time.Parse(time.RFC3339Nano, r.Deadline)
		if err != nil {
			return nil, fmt.Errorf("deadline: %w", err)
		}
		if requested.Before(deadline) {
			deadline = requested
		}
	}
	return &knowledgev1.SearchRequest{
		Scope:      &knowledgev1.Scope{TenantId: s.TenantID, ProjectId: s.ProjectID, ActorId: s.ActorID},
		SnapshotId: r.SnapshotID, Query: r.Query, MaxContextItems: r.MaxContextItems, RetrievalProfileId: r.RetrievalProfileID,
		Deadline: timestamppb.New(deadline.UTC().Truncate(time.Millisecond)),
	}, nil
}

// KnowledgeRelay forwards bound searches to Knowledge's RetrievalService
// under the sidecar's own identity (its workload certificate under mtls,
// plaintext DEVELOPMENT_ONLY).
type KnowledgeRelay struct {
	conn     *grpc.ClientConn
	searches knowledgev1.RetrievalServiceClient
	timeout  time.Duration
}

func NewKnowledgeRelay(address string, files *TLSFiles, timeout time.Duration) (*KnowledgeRelay, error) {
	creds, err := transportCredentials(files)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &KnowledgeRelay{conn: conn, searches: knowledgev1.NewRetrievalServiceClient(conn), timeout: timeout}, nil
}

func (k *KnowledgeRelay) Close() error { return k.conn.Close() }

// Search runs one retrieval; it is a read and never an effect.
func (k *KnowledgeRelay) Search(ctx context.Context, req *knowledgev1.SearchRequest) (*knowledgev1.SearchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()
	return k.searches.Search(ctx, req)
}

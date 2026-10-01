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

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
)

// CallRequest is what the trusted harness may send for a tool call: its
// own command id, the grant revision, the method and the argument object.
// The execution binding, the subject and the digests are the sidecar's.
type CallRequest struct {
	CommandID     string          `json:"commandId"`
	GrantID       string          `json:"grantId"`
	GrantRevision string          `json:"grantRevision"`
	Method        string          `json:"method"`
	Arguments     json.RawMessage `json:"arguments"`
	Deadline      string          `json:"deadline,omitempty"`
}

// ParseCallRequest decodes the caller's bytes strictly.
func ParseCallRequest(raw []byte) (CallRequest, error) {
	var r CallRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return CallRequest{}, err
	}
	if dec.More() {
		return CallRequest{}, errors.New("trailing data")
	}
	if r.CommandID == "" || len(r.CommandID) > 64 || r.GrantID == "" || r.GrantRevision == "" || r.Method == "" || len(r.Arguments) == 0 {
		return CallRequest{}, errors.New("commandId (at most 64 characters), grantId, grantRevision, method and arguments are required")
	}
	return r, nil
}

// BindCall builds MCP's CreateCallRequest: the confirmed scope is the
// execution binding and the subject (the operation's project and actor as
// Control records them), the command id is namespaced by the instance, the
// deadline is the attempt's unless the caller asked for an earlier one,
// the argument digest covers the caller's exact argument bytes and the
// request digest the bound scope and the caller's exact request, so a
// repeated request answers the original call (and never sends again) and a
// changed one conflicts.
func BindCall(s *Scope, r CallRequest, raw []byte) (*mcpv1.CreateCallRequest, error) {
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
	if s.ActorID == "" {
		return nil, errors.New("the operation names no actor")
	}
	bound, _ := json.Marshal(map[string]string{"tenantId": s.TenantID, "projectId": s.ProjectID, "actorId": s.ActorID, "operationId": s.OperationID,
		"attemptId": s.AttemptID, "instanceId": s.InstanceID, "executionEpoch": s.ExecutionEpoch})
	return &mcpv1.CreateCallRequest{
		Command: &mcpv1.CommandIdentity{TenantId: s.TenantID, CommandId: "sidecar:" + s.InstanceID + ":" + r.CommandID, ActorId: s.ActorID,
			RequestDigest: DigestOf(append(append(bound, '\n'), raw...))},
		Scope:   &mcpv1.Scope{TenantId: s.TenantID, ProjectId: s.ProjectID, ActorId: s.ActorID},
		GrantId: r.GrantID, GrantRevision: r.GrantRevision, Method: r.Method, ArgumentRef: "inline", ArgumentDigest: DigestOf(r.Arguments),
		Arguments: r.Arguments, OperationId: s.OperationID, AttemptId: s.AttemptID, InstanceId: s.InstanceID, ExecutionEpoch: s.ExecutionEpoch,
		Deadline: timestamppb.New(deadline.UTC().Truncate(time.Millisecond)),
	}, nil
}

// MCPRelay forwards bound tool calls to MCP's CallService under the
// sidecar's own identity (plaintext DEVELOPMENT_ONLY or its workload
// certificate under mtls).
type MCPRelay struct {
	conn    *grpc.ClientConn
	calls   mcpv1.CallServiceClient
	timeout time.Duration
}

func NewMCPRelay(address string, files *TLSFiles, timeout time.Duration) (*MCPRelay, error) {
	creds, err := transportCredentials(files)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &MCPRelay{conn: conn, calls: mcpv1.NewCallServiceClient(conn), timeout: timeout}, nil
}

func (m *MCPRelay) Close() error { return m.conn.Close() }

// Call creates (or, for the same request, answers) the tool call.
func (m *MCPRelay) Call(ctx context.Context, req *mcpv1.CreateCallRequest) (*mcpv1.CreateCallResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	return m.calls.CreateCall(ctx, req)
}

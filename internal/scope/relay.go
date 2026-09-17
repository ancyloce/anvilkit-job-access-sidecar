package scope

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-contracts/go/modelproxyapi"
)

// The controlled model relay (DD-03 §5 "controlled model relay", delivery.md
// P11): the sidecar forwards a candidate's or the trusted harness's model
// request to the Model Proxy over the frozen transport. The execution
// binding is the scope Control confirmed for this Pod, never the caller's
// word; the request digest binds that scope to the caller's exact bytes;
// the caller's headers are dropped and the sidecar's own identity is
// presented; the Proxy's frames are relayed as they arrive. No provider
// key, no direct provider address and no fallback exist here.

// RelayRequest is what a caller may state: the call identity, the route, the
// content and the bounds. Anything else — a binding, a key, an address — is
// refused by the strict decoder.
type RelayRequest struct {
	CallID          string                         `json:"callId"`
	RouteID         string                         `json:"routeId"`
	Messages        []modelproxyapi.Message        `json:"messages"`
	Tools           []modelproxyapi.ToolDefinition `json:"tools,omitempty"`
	MaxOutputTokens int                            `json:"maxOutputTokens"`
	MaxExposure     modelproxyapi.Money            `json:"maxExposure"`
	Deadline        string                         `json:"deadline,omitempty"`
}

// RelayOptions configures the Proxy client.
type RelayOptions struct {
	URL     string
	Token   string
	TLS     *TLSFiles
	Timeout time.Duration
}

// Relay is the Proxy client of the sidecar.
type Relay struct {
	api     *modelproxyapi.Client
	timeout time.Duration
}

// NewRelay builds the Proxy client with the sidecar's identity: the
// DEVELOPMENT_ONLY bearer token from the environment, or the workload
// certificate files of the mtls identity. Redirects are never followed.
func NewRelay(o RelayOptions) (*Relay, error) {
	if o.URL == "" {
		return nil, errors.New("model relay: url is required")
	}
	if (o.Token == "") == (o.TLS == nil) {
		return nil, errors.New("model relay: exactly one of a bearer token (development) or the mtls identity is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	if o.TLS != nil {
		cert, err := tls.LoadX509KeyPair(o.TLS.CertFile, o.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("model relay: client certificate: %w", err)
		}
		ca, err := os.ReadFile(o.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("model relay: ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("model relay: ca file holds no certificate")
		}
		transport.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: o.TLS.ServerName, MinVersion: tls.VersionTLS13}
	}
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	opts := []modelproxyapi.ClientOption{modelproxyapi.WithHTTPClient(httpClient)}
	if o.Token != "" {
		token := o.Token
		opts = append(opts, modelproxyapi.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		}))
	}
	api, err := modelproxyapi.NewClient(strings.TrimRight(o.URL, "/")+"/api/v1", opts...)
	if err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Relay{api: api, timeout: timeout}, nil
}

// ParseRelayRequest decodes the caller's bytes strictly.
func ParseRelayRequest(raw []byte) (RelayRequest, error) {
	var r RelayRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return RelayRequest{}, err
	}
	if dec.More() {
		return RelayRequest{}, errors.New("trailing data")
	}
	if r.CallID == "" || r.RouteID == "" || len(r.Messages) == 0 || r.MaxOutputTokens < 1 || r.MaxExposure.Currency == "" || r.MaxExposure.Amount == "" {
		return RelayRequest{}, errors.New("callId, routeId, messages, maxOutputTokens and maxExposure are required")
	}
	return r, nil
}

// Bind builds the Proxy request: the confirmed scope is the execution
// binding, the deadline is the attempt's unless the caller asked for an
// earlier one, and the request digest covers the scope and the caller's
// exact bytes so a repeat reenters the same call and a change conflicts.
func Bind(s *Scope, r RelayRequest, raw []byte) (modelproxyapi.ModelCallRequest, error) {
	deadline := s.Deadline
	if r.Deadline != "" {
		requested, err := time.Parse(time.RFC3339Nano, r.Deadline)
		if err != nil {
			return modelproxyapi.ModelCallRequest{}, fmt.Errorf("deadline: %w", err)
		}
		if requested.Before(deadline) {
			deadline = requested
		}
	}
	binding := modelproxyapi.ExecutionBinding{TenantId: s.TenantID, OperationId: s.OperationID, AttemptId: s.AttemptID, ExecutionEpoch: s.ExecutionEpoch}
	if s.InstanceID != "" {
		id := s.InstanceID
		binding.InstanceId = &id
	}
	bound, _ := json.Marshal(binding)
	req := modelproxyapi.ModelCallRequest{
		CallId:          r.CallID,
		Binding:         binding,
		RouteId:         r.RouteID,
		RequestDigest:   DigestOf(append(append(bound, '\n'), raw...)),
		Messages:        r.Messages,
		MaxOutputTokens: r.MaxOutputTokens,
		MaxExposure:     r.MaxExposure,
		Deadline:        deadline.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"),
	}
	if len(r.Tools) > 0 {
		tools := r.Tools
		req.Tools = &tools
	}
	return req, nil
}

// Forward opens the call on the Proxy and copies its answer to w: the error
// envelope of a refusal as it is, the event stream frame by frame as it
// arrives. It returns once the Proxy's answer ended.
func (r *Relay) Forward(ctx context.Context, w http.ResponseWriter, req modelproxyapi.ModelCallRequest, deadline time.Time) error {
	bound := r.timeout
	if until := time.Until(deadline) + 30*time.Second; until > bound {
		bound = until
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	resp, err := r.api.CreateModelCall(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: model proxy: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Connection", "close")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return nil
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(deadline.Add(30 * time.Second))
	_ = rc.Flush()
	reader := bufio.NewReaderSize(resp.Body, 64<<10)
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				return nil // the caller went away; the Proxy's send is not ours to stop
			}
			if len(line) == 1 {
				_ = rc.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			_ = rc.Flush()
			return nil
		}
	}
}

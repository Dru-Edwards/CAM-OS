// Package generated provides temporary stub implementations for CAM-OS protobuf messages
// This file will be replaced when proper protobuf generation is set up
package generated

// Core syscall request/response stubs
type CommitTaskRequest struct {
	Task           *Task
	AgentId        string
	CallerId       string
	AllowRollback  bool
	RollbackPolicy string
	CommitMetadata map[string]string
}

type CommitTaskResponse struct {
	TaskId          string
	CommitId        string
	Error           string
	StatusCode      int32
	RollbackToken   string
	CommitTimestamp int64
}

type TaskRollbackRequest struct {
	TaskId   string
	Reason   string
	CallerId string
}

type TaskRollbackResponse struct {
	TaskId     string
	Success    bool
	Error      string
	StatusCode int32
}

type AgentRegisterRequest struct {
	AgentId      string
	Capabilities []string
	Metadata     map[string]string
	CallerId     string
}

type AgentRegisterResponse struct {
	AgentId    string
	Success    bool
	Error      string
	StatusCode int32
}

type QueryPolicyRequest struct {
	PolicyId string
	Query    string
	CallerId string
	Context  map[string]string
}

type QueryPolicyResponse struct {
	Allowed    bool
	Reason     string
	Error      string
	StatusCode int32
}

type PolicyUpdateRequest struct {
	PolicyId   string
	PolicyData []byte
	Metadata   map[string]string
	CallerId   string
}

type PolicyUpdateResponse struct {
	PolicyId   string
	Version    string
	Error      string
	StatusCode int32
}

// Memory syscall request/response stubs
type ContextReadRequest struct {
	Namespace string
	Key       string
	CallerId  string
	Version   int64
}

type ContextReadResponse struct {
	Data       []byte
	Version    int64
	Hash       string
	Error      string
	StatusCode int32
}

type ContextWriteRequest struct {
	Namespace string
	Key       string
	Data      []byte
	CallerId  string
	Metadata  map[string]string
}

type ContextWriteResponse struct {
	Version    int64
	Hash       string
	Error      string
	StatusCode int32
}

type ContextSnapshotRequest struct {
	Namespace   string
	CallerId    string
	Description string
}

type ContextSnapshotResponse struct {
	SnapshotId string
	Timestamp  int64
	Error      string
	StatusCode int32
}

type ContextRestoreRequest struct {
	SnapshotId string
	CallerId   string
	Force      bool
}

type ContextRestoreResponse struct {
	Namespace     string
	RestoredItems int64
	Error         string
	StatusCode    int32
}

type SnapshotContextRequest struct {
	Namespace   string
	CallerId    string
	Description string
}

type SnapshotContextResponse struct {
	SnapshotId string
	Timestamp  int64
	Error      string
	StatusCode int32
}

type ContextVersionListRequest struct {
	Namespace string
	Key       string
	CallerId  string
	Limit     int32
}

type ContextVersion struct {
	Version   int64
	Hash      string
	Timestamp int64
	Size      int64
	Metadata  map[string]string
}

type ContextVersionListResponse struct {
	Versions   []*ContextVersion
	Error      string
	StatusCode int32
}

// Security syscall request/response stubs
type TmpSignRequest struct {
	Data     []byte
	CallerId string
	KeyId    string
}

type TmpSignResponse struct {
	Signature  []byte
	Algorithm  string
	Error      string
	StatusCode int32
	KeyId      string
	KeyHandle  string
	CertChain  [][]byte
	Timestamp  int64
}

type VerifyManifestRequest struct {
	Manifest  []byte
	Signature []byte
	PublicKey []byte
	CallerId  string
}

type VerifyManifestResponse struct {
	Valid      bool
	Issuer     string
	ExpiresAt  int64
	Error      string
	StatusCode int32
	TrustLevel float64
	Warnings   []string
}

type EstablishSecureChannelRequest struct {
	PeerId   string
	Protocol string
	CallerId string
}

type EstablishSecureChannelResponse struct {
	ChannelId  string
	SessionKey []byte
	Error      string
	StatusCode int32
	Protocol   string
	ExpiresAt  int64
}

// Observability syscall request/response stubs
type ExplainActionRequest struct {
	TraceId          string
	CallerId         string
	IncludeReasoning bool
}

type ExplainActionResponse struct {
	Explanation    string
	ReasoningChain []string
	Evidence       []string
	Error          string
	StatusCode     int32
	Confidence     float64
	TrustScore     float64
}

type EmitTraceRequest struct {
	TraceId       string
	SpanId        string
	OperationName string
	StartTime     int64
	EndTime       int64
	Tags          map[string]string
	CallerId      string
}

type EmitTraceResponse struct {
	TraceId    string
	Error      string
	StatusCode int32
}

type EmitMetricRequest struct {
	Name      string
	Value     float64
	Type      string
	Labels    map[string]string
	Timestamp int64
	CallerId  string
}

type EmitMetricResponse struct {
	MetricId   string
	Error      string
	StatusCode int32
}

type SystemTuningRequest struct {
	Parameters    map[string]string
	TuningProfile string
	DryRun        bool
	CallerId      string
}

type SystemTuningResponse struct {
	AppliedParameters  map[string]string
	RejectedParameters map[string]string
	Warnings           []string
	RequiresRestart    bool
	Error              string
	StatusCode         int32
}

// Implement minimal methods to satisfy interfaces
func (x *CommitTaskRequest) GetTask() *Task { if x != nil { return x.Task }; return nil }
func (x *CommitTaskRequest) GetAgentId() string { if x != nil { return x.AgentId }; return "" }
func (x *CommitTaskRequest) GetCallerId() string { if x != nil { return x.CallerId }; return "" }

func (x *CommitTaskResponse) GetTaskId() string { if x != nil { return x.TaskId }; return "" }
func (x *CommitTaskResponse) GetCommitId() string { if x != nil { return x.CommitId }; return "" }
func (x *CommitTaskResponse) GetError() string { if x != nil { return x.Error }; return "" }
func (x *CommitTaskResponse) GetStatusCode() int32 { if x != nil { return x.StatusCode }; return 0 }

func (x *TaskRollbackRequest) GetTaskId() string { if x != nil { return x.TaskId }; return "" }
func (x *TaskRollbackRequest) GetReason() string { if x != nil { return x.Reason }; return "" }
func (x *TaskRollbackRequest) GetCallerId() string { if x != nil { return x.CallerId }; return "" }

func (x *TaskRollbackResponse) GetTaskId() string { if x != nil { return x.TaskId }; return "" }
func (x *TaskRollbackResponse) GetStatusCode() int32 { if x != nil { return x.StatusCode }; return 0 }

func (x *AgentRegisterRequest) GetAgentId() string { if x != nil { return x.AgentId }; return "" }
func (x *AgentRegisterRequest) GetCapabilities() []string { if x != nil { return x.Capabilities }; return nil }
func (x *AgentRegisterRequest) GetMetadata() map[string]string { if x != nil { return x.Metadata }; return nil }
func (x *AgentRegisterRequest) GetCallerId() string { if x != nil { return x.CallerId }; return "" }

func (x *AgentRegisterResponse) GetAgentId() string { if x != nil { return x.AgentId }; return "" }
func (x *AgentRegisterResponse) GetStatusCode() int32 { if x != nil { return x.StatusCode }; return 0 }

func (x *QueryPolicyRequest) GetPolicyId() string { if x != nil { return x.PolicyId }; return "" }
func (x *QueryPolicyRequest) GetQuery() string { if x != nil { return x.Query }; return "" }
func (x *QueryPolicyRequest) GetCallerId() string { if x != nil { return x.CallerId }; return "" }
func (x *QueryPolicyRequest) GetContext() map[string]string { if x != nil { return x.Context }; return nil }

func (x *QueryPolicyResponse) GetAllowed() bool { if x != nil { return x.Allowed }; return false }
func (x *QueryPolicyResponse) GetReason() string { if x != nil { return x.Reason }; return "" }
func (x *QueryPolicyResponse) GetError() string { if x != nil { return x.Error }; return "" }
func (x *QueryPolicyResponse) GetStatusCode() int32 { if x != nil { return x.StatusCode }; return 0 }

func (x *PolicyUpdateRequest) GetPolicyId() string { if x != nil { return x.PolicyId }; return "" }
func (x *PolicyUpdateRequest) GetPolicyData() []byte { if x != nil { return x.PolicyData }; return nil }
func (x *PolicyUpdateRequest) GetMetadata() map[string]string { if x != nil { return x.Metadata }; return nil }
func (x *PolicyUpdateRequest) GetCallerId() string { if x != nil { return x.CallerId }; return "" }

func (x *PolicyUpdateResponse) GetPolicyId() string { if x != nil { return x.PolicyId }; return "" }
func (x *PolicyUpdateResponse) GetVersion() string { if x != nil { return x.Version }; return "" }
func (x *PolicyUpdateResponse) GetError() string { if x != nil { return x.Error }; return "" }
func (x *PolicyUpdateResponse) GetStatusCode() int32 { if x != nil { return x.StatusCode }; return 0 } 
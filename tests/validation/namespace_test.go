package validation

import (
	"testing"

	"github.com/cam-os/kernel/internal/validation"
)

func TestValidateNamespace(t *testing.T) {
	testCases := []struct {
		name      string
		namespace string
		wantErr   bool
	}{
		{
			name:      "valid namespace",
			namespace: "test-namespace",
			wantErr:   false,
		},
		{
			name:      "valid namespace with underscore",
			namespace: "test_namespace",
			wantErr:   false,
		},
		{
			name:      "valid namespace with numbers",
			namespace: "test123",
			wantErr:   false,
		},
		{
			name:      "empty namespace",
			namespace: "",
			wantErr:   true,
		},
		{
			name:      "namespace too long",
			namespace: "this-is-a-very-long-namespace-name-that-exceeds-the-maximum-length",
			wantErr:   true,
		},
		{
			name:      "namespace with directory traversal",
			namespace: "../etc",
			wantErr:   true,
		},
		{
			name:      "namespace with forward slash",
			namespace: "test/namespace",
			wantErr:   true,
		},
		{
			name:      "namespace starting with dot",
			namespace: ".hidden",
			wantErr:   true,
		},
		{
			name:      "namespace with uppercase letters",
			namespace: "TestNamespace",
			wantErr:   true,
		},
		{
			name:      "namespace with null byte",
			namespace: "test\x00namespace",
			wantErr:   true,
		},
		{
			name:      "namespace with control character",
			namespace: "test\x01namespace",
			wantErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validation.ValidateNamespace(tc.namespace)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for namespace %q, got nil", tc.namespace)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for namespace %q: %v", tc.namespace, err)
			}
		})
	}
}

func TestValidateKey(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid key",
			key:     "valid-key",
			wantErr: false,
		},
		{
			name:    "valid key with path",
			key:     "path/to/key",
			wantErr: false,
		},
		{
			name:    "valid key with dot",
			key:     "config.yaml",
			wantErr: false,
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: true,
		},
		{
			name:    "key too long",
			key:     "this-is-a-very-long-key-name-that-exceeds-the-maximum-length-of-256-characters-and-should-be-rejected-by-the-validation-function-because-it-is-too-long-to-be-a-valid-key-name-for-the-cam-os-system-and-could-cause-problems-with-storage-and-retrieval-operations",
			wantErr: true,
		},
		{
			name:    "key with directory traversal",
			key:     "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "key with null byte",
			key:     "key\x00name",
			wantErr: true,
		},
		{
			name:    "key with control character",
			key:     "key\x01name",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validation.ValidateKey(tc.key)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for key %q, got nil", tc.key)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for key %q: %v", tc.key, err)
			}
		})
	}
}

func TestValidateAgentID(t *testing.T) {
	testCases := []struct {
		name    string
		agentID string
		wantErr bool
	}{
		{
			name:    "valid agent ID",
			agentID: "agent-123",
			wantErr: false,
		},
		{
			name:    "valid agent ID with underscore",
			agentID: "agent_123",
			wantErr: false,
		},
		{
			name:    "empty agent ID",
			agentID: "",
			wantErr: true,
		},
		{
			name:    "agent ID too long",
			agentID: "this-is-a-very-long-agent-id-that-exceeds-the-maximum-length-of-128-characters-and-should-be-rejected-by-validation-because-it-is-really-too-long-to-be-accepted",
			wantErr: true,
		},
		{
			name:    "agent ID with slash",
			agentID: "agent/123",
			wantErr: true,
		},
		{
			name:    "agent ID with dot",
			agentID: "agent.123",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validation.ValidateAgentID(tc.agentID)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for agent ID %q, got nil", tc.agentID)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for agent ID %q: %v", tc.agentID, err)
			}
		})
	}
}

func TestValidateNamespaceAndKey(t *testing.T) {
	testCases := []struct {
		name      string
		namespace string
		key       string
		wantErr   bool
	}{
		{
			name:      "valid namespace and key",
			namespace: "test-namespace",
			key:       "test-key",
			wantErr:   false,
		},
		{
			name:      "invalid namespace",
			namespace: "../etc",
			key:       "valid-key",
			wantErr:   true,
		},
		{
			name:      "invalid key",
			namespace: "valid-namespace",
			key:       "../../../etc/passwd",
			wantErr:   true,
		},
		{
			name:      "both invalid",
			namespace: ".hidden",
			key:       "../secret",
			wantErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validation.ValidateNamespaceAndKey(tc.namespace, tc.key)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for namespace %q and key %q, got nil", tc.namespace, tc.key)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for namespace %q and key %q: %v", tc.namespace, tc.key, err)
			}
		})
	}
}

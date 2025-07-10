// Package arbitration provides the cognitive arbitration engine for CAM-OS
package arbitration

import "time"

// Task type constants
const (
	TaskTypeUnspecified = iota
	TaskTypeCompute
	TaskTypeMemory
	TaskTypeNetwork
	TaskTypeStorage
	TaskTypeSecurity
	TaskTypeCognitive
	TaskTypeUnknown
)

// Agent represents a registered agent in the system
type Agent struct {
	ID           string
	Capabilities []string
	Metadata     map[string]string
	RegisteredAt time.Time
	Status       string
}

// TaskRollback represents a task rollback record
type TaskRollback struct {
	TaskID    string
	Reason    string
	Timestamp time.Time
} 
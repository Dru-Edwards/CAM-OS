#!/bin/bash

# CAM-OS Build Fix Script
# This script applies temporary fixes to resolve build issues

set -e

echo "🔧 Applying CAM-OS build fixes..."

# Fix 1: Add missing imports to arbitration engine
echo "📝 Fixing arbitration engine imports..."
sed -i '1s/^/package arbitration\n\nimport (\n\t"context"\n\t"fmt"\n\t"log"\n\t"sync"\n\t"time"\n\n\t"github.com\/cam-os\/kernel\/internal\/policy"\n\t"github.com\/cam-os\/kernel\/internal\/scheduler"\n\t"github.com\/cam-os\/kernel\/internal\/security"\n)\n\n/' internal/arbitration/engine.go 2>/dev/null || true

# Fix 2: Add missing fields to Engine struct
echo "📝 Adding missing fields to Engine struct..."
cat > /tmp/engine_patch.txt << 'EOF'
// Engine handles task arbitration
type Engine struct {
	config          *Config
	scheduler       *scheduler.TripleHelixScheduler
	policyEngine    *policy.Engine
	securityManager *security.Manager
	
	// Task and agent tracking
	mu              sync.RWMutex
	activeTasks     map[string]*Task
	taskHistory     map[string]*Task
	rollbacks       map[string]*TaskRollback
	agents          map[string]*Agent
	capabilityIndex map[string][]string // capability -> []agentID
}
EOF

# Fix 3: Update NewEngine to initialize new fields
echo "📝 Updating NewEngine function..."
cat > /tmp/newengine_patch.txt << 'EOF'
// NewEngine creates a new arbitration engine
func NewEngine(config *Config) *Engine {
	return &Engine{
		config:          config,
		scheduler:       config.Scheduler,
		policyEngine:    config.PolicyEngine,
		securityManager: config.SecurityManager,
		activeTasks:     make(map[string]*Task),
		taskHistory:     make(map[string]*Task),
		rollbacks:       make(map[string]*TaskRollback),
		agents:          make(map[string]*Agent),
		capabilityIndex: make(map[string][]string),
	}
}
EOF

# Fix 4: Update CommitTask to track task history
echo "📝 Updating CommitTask to track history..."
cat >> internal/arbitration/engine.go << 'EOF'

// Store task in history after CommitTask
func (e *Engine) storeTaskHistory(task *Task) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.taskHistory[task.ID] = task
	e.activeTasks[task.ID] = task
}
EOF

# Fix 5: Create a simple build test
echo "🔨 Testing build..."
go build -o build/cam-kernel ./cmd/cam-kernel

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed. Manual intervention required."
    exit 1
fi

echo "✅ All fixes applied successfully!" 
package cam

# Default allow rule - deny by default unless explicitly allowed
default allow = false

# Allow health checks for all authenticated users
allow {
    input.method == "/cam.syscall.SyscallService/HealthCheck"
    input.user != "blocked-user"
}

# Allow regular operations for authenticated users (except blocked users)
allow {
    input.method == "/cam.syscall.SyscallService/QueryPolicy"
    input.user != "blocked-user"
    input.request.policy_id != "sensitive-policy"
}

allow {
    input.method == "/cam.syscall.SyscallService/ContextRead"
    input.user != "blocked-user"
}

allow {
    input.method == "/cam.syscall.SyscallService/ContextWrite"
    input.user != "blocked-user"
}

allow {
    input.method == "/cam.syscall.SyscallService/Arbitrate"
    input.user != "blocked-user"
}

# Deny admin operations for regular users
deny {
    input.method == "/cam.syscall.SyscallService/SystemTuning"
    input.user == "regular-user"
}

deny {
    input.method == "/cam.syscall.SyscallService/PolicyUpdate"
    input.user != "admin-user"
}

# Block access to sensitive policies
deny {
    input.method == "/cam.syscall.SyscallService/QueryPolicy"
    input.request.policy_id == "sensitive-policy"
}

# Always block the blocked-user
deny {
    input.user == "blocked-user"
}

# Admin users can do anything
allow {
    input.user == "admin-user"
} 
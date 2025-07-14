# CAM Performance Test Data Fixtures
# Baseline performance data for comparison and regression testing

baseline_performance_data = {
    "metadata": {
        "version": "1.0.0",
        "created_date": "2025-05-23",
        "environment": "production_baseline",
        "test_duration_minutes": 30,
        "description": "Baseline performance metrics for CAM system under normal operating conditions"
    },
    
    "system_requirements": {
        "community_tier": {
            "p95_response_time_ms": 500,
            "max_error_rate_percent": 1.0,
            "min_throughput_rps": 10,
            "arbitration_decision_time_ms": 300
        },
        "professional_tier": {
            "p95_response_time_ms": 250,
            "max_error_rate_percent": 0.5,
            "min_throughput_rps": 50,
            "arbitration_decision_time_ms": 150
        },
        "enterprise_tier": {
            "p95_response_time_ms": 100,
            "max_error_rate_percent": 0.1,
            "min_throughput_rps": 200,
            "arbitration_decision_time_ms": 75
        }
    },
    
    "baseline_metrics": {
        "http_req_duration": {
            "avg": 145.2,
            "min": 23.1,
            "max": 891.7,
            "p50": 128.4,
            "p95": 287.9,
            "p99": 456.3,
            "count": 15672
        },
        "http_req_failed": {
            "rate": 0.0032,
            "count": 50
        },
        "arbitration_decision_time": {
            "avg": 89.6,
            "min": 15.2,
            "max": 324.8,
            "p50": 78.3,
            "p95": 156.7,
            "p99": 243.1,
            "count": 5224
        },
        "provider_selection_accuracy": {
            "rate": 0.947,
            "total_selections": 5224,
            "successful_selections": 4946
        },
        "cost_optimization_rate": {
            "rate": 0.823,
            "total_optimizations": 5224,
            "successful_optimizations": 4299,
            "average_savings_percent": 18.7
        },
        "agent_collaboration_efficiency": {
            "rate": 0.891,
            "total_collaborations": 1247,
            "successful_collaborations": 1111,
            "average_sync_time_ms": 456.2
        }
    },
    
    "load_test_scenarios": {
        "basic_load": {
            "concurrent_users": 10,
            "duration_minutes": 5,
            "ramp_up_time_seconds": 30,
            "expected_rps": 25,
            "expected_p95_ms": 200
        },
        "moderate_load": {
            "concurrent_users": 50,
            "duration_minutes": 10,
            "ramp_up_time_seconds": 60,
            "expected_rps": 125,
            "expected_p95_ms": 300
        },
        "heavy_load": {
            "concurrent_users": 100,
            "duration_minutes": 15,
            "ramp_up_time_seconds": 120,
            "expected_rps": 200,
            "expected_p95_ms": 450
        },
        "peak_load": {
            "concurrent_users": 200,
            "duration_minutes": 10,
            "ramp_up_time_seconds": 180,
            "expected_rps": 300,
            "expected_p95_ms": 600
        },
        "spike_load": {
            "concurrent_users": 500,
            "duration_minutes": 5,
            "ramp_up_time_seconds": 30,
            "expected_rps": 400,
            "expected_p95_ms": 1000
        },
        "endurance_load": {
            "concurrent_users": 25,
            "duration_minutes": 60,
            "ramp_up_time_seconds": 300,
            "expected_rps": 60,
            "expected_p95_ms": 250
        }
    },
    
    "stress_test_thresholds": {
        "memory_stress": {
            "max_memory_usage_percent": 85,
            "memory_leak_threshold_mb": 100,
            "gc_frequency_threshold": 50
        },
        "cpu_stress": {
            "max_cpu_usage_percent": 90,
            "sustained_high_cpu_minutes": 5,
            "cpu_throttling_threshold": 0.1
        },
        "network_stress": {
            "max_network_latency_ms": 2000,
            "packet_loss_threshold_percent": 1,
            "bandwidth_saturation_threshold": 0.9
        },
        "concurrency_stress": {
            "max_concurrent_connections": 1000,
            "connection_timeout_seconds": 30,
            "deadlock_detection_enabled": True
        }
    },
    
    "benchmark_targets": {
        "arbitration_performance": {
            "simple_queries": {
                "target_p95_ms": 100,
                "target_accuracy_rate": 0.95,
                "target_cost_optimization": 0.8
            },
            "complex_queries": {
                "target_p95_ms": 500,
                "target_accuracy_rate": 0.9,
                "target_cost_optimization": 0.7
            },
            "multi_model_queries": {
                "target_p95_ms": 1000,
                "target_accuracy_rate": 0.85,
                "target_cost_optimization": 0.6
            }
        },
        "agent_collaboration": {
            "sequential_collaboration": {
                "target_efficiency_rate": 0.9,
                "target_sync_time_ms": 1000,
                "target_coordination_accuracy": 0.95
            },
            "parallel_collaboration": {
                "target_efficiency_rate": 0.85,
                "target_sync_time_ms": 800,
                "target_coordination_accuracy": 0.9
            },
            "hierarchical_collaboration": {
                "target_efficiency_rate": 0.8,
                "target_sync_time_ms": 1500,
                "target_coordination_accuracy": 0.88
            }
        },
        "cost_optimization": {
            "basic_optimization": {
                "target_savings_percent": 15,
                "target_accuracy_rate": 0.9,
                "target_budget_compliance": 0.95
            },
            "advanced_optimization": {
                "target_savings_percent": 25,
                "target_accuracy_rate": 0.85,
                "target_budget_compliance": 0.9
            },
            "budget_constrained": {
                "target_savings_percent": 20,
                "target_accuracy_rate": 0.88,
                "target_budget_compliance": 0.98
            }
        }
    },
    
    "environment_configurations": {
        "development": {
            "scale_factor": 0.1,
            "mock_providers": True,
            "debug_logging": True,
            "cache_disabled": True
        },
        "staging": {
            "scale_factor": 0.5,
            "mock_providers": False,
            "debug_logging": False,
            "cache_enabled": True
        },
        "production": {
            "scale_factor": 1.0,
            "mock_providers": False,
            "debug_logging": False,
            "cache_enabled": True,
            "monitoring_enabled": True
        }
    },
    
    "test_data_sets": {
        "simple_prompts": [
            "What is the capital of France?",
            "Explain photosynthesis in simple terms",
            "Calculate 15% of 240",
            "What year did World War II end?",
            "Define machine learning"
        ],
        "moderate_prompts": [
            "Compare the advantages and disadvantages of renewable energy sources",
            "Explain the economic impact of artificial intelligence on job markets",
            "Analyze the causes and effects of climate change",
            "Describe the process of protein synthesis in cells",
            "Evaluate different investment strategies for retirement planning"
        ],
        "complex_prompts": [
            "Develop a comprehensive business strategy for expanding a tech startup into emerging markets, considering economic, political, and cultural factors across three different regions",
            "Create a detailed analysis of the global supply chain disruptions' impact on the automotive industry, including risk assessment, mitigation strategies, and financial projections for the next five years",
            "Design a multi-layered cybersecurity framework for a healthcare organization that handles sensitive patient data, including compliance requirements, threat modeling, and incident response procedures"
        ],
        "collaboration_tasks": [
            "Multi-agent market analysis with risk assessment and recommendation synthesis",
            "Collaborative research project with data collection, analysis, and report generation",
            "Strategic planning session with multiple perspectives and consensus building",
            "Product development lifecycle with design, engineering, and marketing input",
            "Crisis management simulation with coordinated response planning"
        ]
    },
    
    "performance_monitoring": {
        "key_metrics": [
            "response_time_p95",
            "error_rate",
            "throughput_rps",
            "arbitration_decision_time",
            "provider_selection_accuracy",
            "cost_optimization_effectiveness",
            "agent_collaboration_efficiency",
            "resource_utilization"
        ],
        "alert_thresholds": {
            "response_time_degradation_percent": 20,
            "error_rate_spike_percent": 50,
            "throughput_drop_percent": 30,
            "memory_usage_critical_percent": 90,
            "cpu_usage_critical_percent": 85
        },
        "regression_detection": {
            "enabled": True,
            "comparison_window_days": 7,
            "significance_threshold_percent": 15,
            "alert_on_regression": True
        }
    }
}

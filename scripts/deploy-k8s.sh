#!/bin/bash
set -euo pipefail

# CAM Protocol Kubernetes Deployment Script
# This script deploys CAM to a Kubernetes cluster

# Configuration
NAMESPACE="cam-system"
DEPLOYMENT_DIR="$(dirname "$0")/../deployment/kubernetes"
ENVIRONMENT="${1:-staging}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        log_warning "helm is not installed - Helm charts will be skipped"
    fi
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Check your kubeconfig."
        exit 1
    fi
    
    log_success "Prerequisites check completed"
}

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE already exists"
    else
        kubectl create namespace "$NAMESPACE"
        kubectl label namespace "$NAMESPACE" istio-injection=enabled --overwrite
        log_success "Namespace $NAMESPACE created"
    fi
}

# Deploy infrastructure components
deploy_infrastructure() {
    log_info "Deploying infrastructure components..."
    
    # Deploy Redis
    log_info "Deploying Redis..."
    kubectl apply -f "$DEPLOYMENT_DIR/redis-deployment.yaml"
    
    # Deploy PostgreSQL
    log_info "Deploying PostgreSQL..."
    kubectl apply -f "$DEPLOYMENT_DIR/postgres-deployment.yaml"
    
    # Wait for infrastructure to be ready
    log_info "Waiting for infrastructure to be ready..."
    kubectl wait --for=condition=ready pod -l app=cam-redis -n "$NAMESPACE" --timeout=300s
    kubectl wait --for=condition=ready pod -l app=cam-postgres -n "$NAMESPACE" --timeout=300s
    
    log_success "Infrastructure components deployed"
}

# Deploy monitoring
deploy_monitoring() {
    log_info "Deploying monitoring components..."
    
    # Deploy Prometheus
    kubectl apply -f "$DEPLOYMENT_DIR/monitoring.yaml"
    
    # Wait for Prometheus to be ready
    kubectl wait --for=condition=ready pod -l app=prometheus -n "$NAMESPACE" --timeout=300s
    
    log_success "Monitoring components deployed"
}

# Deploy application
deploy_application() {
    log_info "Deploying CAM application..."
    
    # Update image tag based on environment
    local image_tag
    if [ "$ENVIRONMENT" = "production" ]; then
        image_tag="latest"
    else
        image_tag="develop"
    fi
    
    # Apply deployment with image tag
    sed "s|ghcr.io/cam-protocol/complete-arbitration-mesh:latest|ghcr.io/cam-protocol/complete-arbitration-mesh:$image_tag|g" \
        "$DEPLOYMENT_DIR/cam-deployment.yaml" | kubectl apply -f -
    
    # Wait for application to be ready
    log_info "Waiting for application to be ready..."
    kubectl wait --for=condition=ready pod -l app=cam-arbitration-mesh -n "$NAMESPACE" --timeout=300s
    
    log_success "CAM application deployed"
}

# Deploy ingress
deploy_ingress() {
    log_info "Deploying ingress..."
    
    # Check if NGINX Ingress Controller is installed
    if ! kubectl get ingressclass nginx &> /dev/null; then
        log_warning "NGINX Ingress Controller not found. Installing..."
        helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
        helm repo update
        helm install ingress-nginx ingress-nginx/ingress-nginx \
            --namespace ingress-nginx \
            --create-namespace \
            --set controller.replicaCount=2 \
            --set controller.nodeSelector."kubernetes\.io/os"=linux \
            --set defaultBackend.nodeSelector."kubernetes\.io/os"=linux
        
        # Wait for ingress controller
        kubectl wait --namespace ingress-nginx \
            --for=condition=ready pod \
            --selector=app.kubernetes.io/component=controller \
            --timeout=300s
    fi
    
    # Apply ingress configuration
    kubectl apply -f "$DEPLOYMENT_DIR/ingress.yaml"
    
    log_success "Ingress deployed"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pod status
    log_info "Checking pod status..."
    kubectl get pods -n "$NAMESPACE"
    
    # Check service status
    log_info "Checking service status..."
    kubectl get services -n "$NAMESPACE"
    
    # Check ingress status
    log_info "Checking ingress status..."
    kubectl get ingress -n "$NAMESPACE"
    
    # Run health check
    log_info "Running health check..."
    local service_ip
    service_ip=$(kubectl get service cam-arbitration-mesh-service -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    
    if kubectl run temp-pod --rm -i --tty --image=curlimages/curl -- \
        curl -f "http://$service_ip/health" &> /dev/null; then
        log_success "Health check passed"
    else
        log_error "Health check failed"
        return 1
    fi
    
    log_success "Deployment verification completed"
}

# Rollback deployment
rollback_deployment() {
    log_warning "Rolling back deployment..."
    
    kubectl rollout undo deployment/cam-arbitration-mesh -n "$NAMESPACE"
    kubectl rollout status deployment/cam-arbitration-mesh -n "$NAMESPACE"
    
    log_success "Rollback completed"
}

# Show deployment status
show_status() {
    log_info "Current deployment status:"
    
    echo ""
    echo "Pods:"
    kubectl get pods -n "$NAMESPACE" -o wide
    
    echo ""
    echo "Services:"
    kubectl get services -n "$NAMESPACE"
    
    echo ""
    echo "Ingress:"
    kubectl get ingress -n "$NAMESPACE"
    
    echo ""
    echo "Recent events:"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -10
}

# Cleanup deployment
cleanup_deployment() {
    log_warning "Cleaning up deployment..."
    
    read -p "Are you sure you want to delete the entire CAM deployment? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl delete namespace "$NAMESPACE"
        log_success "Cleanup completed"
    else
        log_info "Cleanup cancelled"
    fi
}

# Main function
main() {
    local command="${2:-deploy}"
    
    echo "CAM Protocol Kubernetes Deployment Script"
    echo "Environment: $ENVIRONMENT"
    echo "Namespace: $NAMESPACE"
    echo "Command: $command"
    echo ""
    
    case "$command" in
        "deploy")
            check_prerequisites
            create_namespace
            deploy_infrastructure
            deploy_monitoring
            deploy_application
            deploy_ingress
            verify_deployment
            log_success "Deployment completed successfully!"
            show_status
            ;;
        "rollback")
            rollback_deployment
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            cleanup_deployment
            ;;
        *)
            echo "Usage: $0 <environment> <command>"
            echo "Environments: staging, production"
            echo "Commands: deploy, rollback, status, cleanup"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"

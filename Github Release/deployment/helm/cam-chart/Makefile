# Makefile for Complete Arbitration Mesh Helm Chart

# Variables
CHART_NAME := cam-chart
RELEASE_NAME := cam
NAMESPACE := default
KUBECONFIG := ~/.kube/config
HELM_VERSION := v3.12.0

# Helm repository settings
REPO_NAME := cam-charts
REPO_URL := https://charts.cam-protocol.io

# Environment-specific values files
DEV_VALUES := values-dev.yaml
STAGING_VALUES := values-staging.yaml
PROD_VALUES := values-prod.yaml

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

.PHONY: help lint template install upgrade uninstall test package clean dev staging prod

# Default target
help: ## Show this help message
	@echo "$(BLUE)Complete Arbitration Mesh Helm Chart Management$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development and validation
lint: ## Lint the Helm chart
	@echo "$(BLUE)Linting Helm chart...$(NC)"
	helm lint .
	@echo "$(GREEN)✓ Chart linting completed$(NC)"

template: ## Generate Kubernetes manifests without installing
	@echo "$(BLUE)Generating Kubernetes templates...$(NC)"
	helm template $(RELEASE_NAME) . --output-dir ./output
	@echo "$(GREEN)✓ Templates generated in ./output$(NC)"

template-dev: ## Generate templates with development values
	@echo "$(BLUE)Generating development templates...$(NC)"
	helm template $(RELEASE_NAME) . -f $(DEV_VALUES) --output-dir ./output-dev
	@echo "$(GREEN)✓ Development templates generated in ./output-dev$(NC)"

template-staging: ## Generate templates with staging values
	@echo "$(BLUE)Generating staging templates...$(NC)"
	helm template $(RELEASE_NAME) . -f $(STAGING_VALUES) --output-dir ./output-staging
	@echo "$(GREEN)✓ Staging templates generated in ./output-staging$(NC)"

template-prod: ## Generate templates with production values
	@echo "$(BLUE)Generating production templates...$(NC)"
	helm template $(RELEASE_NAME) . -f $(PROD_VALUES) --output-dir ./output-prod
	@echo "$(GREEN)✓ Production templates generated in ./output-prod$(NC)"

# Installation and management
install: ## Install the chart with default values
	@echo "$(BLUE)Installing CAM chart...$(NC)"
	helm install $(RELEASE_NAME) . --namespace $(NAMESPACE) --create-namespace
	@echo "$(GREEN)✓ Chart installed successfully$(NC)"
	@echo "$(YELLOW)Run 'make status' to check deployment status$(NC)"

install-dev: ## Install with development values
	@echo "$(BLUE)Installing CAM chart for development...$(NC)"
	helm install $(RELEASE_NAME)-dev . -f $(DEV_VALUES) --namespace cam-dev --create-namespace
	@echo "$(GREEN)✓ Development chart installed successfully$(NC)"

install-staging: ## Install with staging values
	@echo "$(BLUE)Installing CAM chart for staging...$(NC)"
	helm install $(RELEASE_NAME)-staging . -f $(STAGING_VALUES) --namespace cam-staging --create-namespace
	@echo "$(GREEN)✓ Staging chart installed successfully$(NC)"

install-prod: ## Install with production values
	@echo "$(BLUE)Installing CAM chart for production...$(NC)"
	@echo "$(RED)⚠️  Make sure you have reviewed and customized the production values!$(NC)"
	@read -p "Are you sure you want to install to production? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		helm install $(RELEASE_NAME)-prod . -f $(PROD_VALUES) --namespace cam-prod --create-namespace; \
		echo "$(GREEN)✓ Production chart installed successfully$(NC)"; \
	else \
		echo "$(YELLOW)Installation cancelled$(NC)"; \
	fi

upgrade: ## Upgrade the chart with default values
	@echo "$(BLUE)Upgrading CAM chart...$(NC)"
	helm upgrade $(RELEASE_NAME) . --namespace $(NAMESPACE)
	@echo "$(GREEN)✓ Chart upgraded successfully$(NC)"

upgrade-dev: ## Upgrade development deployment
	@echo "$(BLUE)Upgrading development CAM chart...$(NC)"
	helm upgrade $(RELEASE_NAME)-dev . -f $(DEV_VALUES) --namespace cam-dev
	@echo "$(GREEN)✓ Development chart upgraded successfully$(NC)"

upgrade-staging: ## Upgrade staging deployment
	@echo "$(BLUE)Upgrading staging CAM chart...$(NC)"
	helm upgrade $(RELEASE_NAME)-staging . -f $(STAGING_VALUES) --namespace cam-staging
	@echo "$(GREEN)✓ Staging chart upgraded successfully$(NC)"

upgrade-prod: ## Upgrade production deployment
	@echo "$(BLUE)Upgrading production CAM chart...$(NC)"
	@echo "$(RED)⚠️  This will upgrade the production deployment!$(NC)"
	@read -p "Are you sure you want to upgrade production? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		helm upgrade $(RELEASE_NAME)-prod . -f $(PROD_VALUES) --namespace cam-prod; \
		echo "$(GREEN)✓ Production chart upgraded successfully$(NC)"; \
	else \
		echo "$(YELLOW)Upgrade cancelled$(NC)"; \
	fi

uninstall: ## Uninstall the chart
	@echo "$(BLUE)Uninstalling CAM chart...$(NC)"
	helm uninstall $(RELEASE_NAME) --namespace $(NAMESPACE)
	@echo "$(GREEN)✓ Chart uninstalled successfully$(NC)"

uninstall-dev: ## Uninstall development deployment
	@echo "$(BLUE)Uninstalling development CAM chart...$(NC)"
	helm uninstall $(RELEASE_NAME)-dev --namespace cam-dev
	@echo "$(GREEN)✓ Development chart uninstalled successfully$(NC)"

uninstall-staging: ## Uninstall staging deployment
	@echo "$(BLUE)Uninstalling staging CAM chart...$(NC)"
	helm uninstall $(RELEASE_NAME)-staging --namespace cam-staging
	@echo "$(GREEN)✓ Staging chart uninstalled successfully$(NC)"

uninstall-prod: ## Uninstall production deployment
	@echo "$(RED)⚠️  This will completely remove the production deployment!$(NC)"
	@read -p "Are you sure you want to uninstall production? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		helm uninstall $(RELEASE_NAME)-prod --namespace cam-prod; \
		echo "$(GREEN)✓ Production chart uninstalled successfully$(NC)"; \
	else \
		echo "$(YELLOW)Uninstall cancelled$(NC)"; \
	fi

# Testing
test: ## Run Helm tests
	@echo "$(BLUE)Running Helm tests...$(NC)"
	helm test $(RELEASE_NAME) --namespace $(NAMESPACE)
	@echo "$(GREEN)✓ Tests completed$(NC)"

test-dev: ## Run tests for development deployment
	@echo "$(BLUE)Running development tests...$(NC)"
	helm test $(RELEASE_NAME)-dev --namespace cam-dev
	@echo "$(GREEN)✓ Development tests completed$(NC)"

test-staging: ## Run tests for staging deployment
	@echo "$(BLUE)Running staging tests...$(NC)"
	helm test $(RELEASE_NAME)-staging --namespace cam-staging
	@echo "$(GREEN)✓ Staging tests completed$(NC)"

test-prod: ## Run tests for production deployment
	@echo "$(BLUE)Running production tests...$(NC)"
	helm test $(RELEASE_NAME)-prod --namespace cam-prod
	@echo "$(GREEN)✓ Production tests completed$(NC)"

# Status and debugging
status: ## Check deployment status
	@echo "$(BLUE)Checking deployment status...$(NC)"
	kubectl get pods,svc,ingress -l app.kubernetes.io/instance=$(RELEASE_NAME) --namespace $(NAMESPACE)

status-all: ## Check status of all environments
	@echo "$(BLUE)Checking all environment statuses...$(NC)"
	@echo "$(YELLOW)Development:$(NC)"
	@kubectl get pods,svc,ingress -l app.kubernetes.io/instance=$(RELEASE_NAME)-dev --namespace cam-dev 2>/dev/null || echo "Development not deployed"
	@echo "$(YELLOW)Staging:$(NC)"
	@kubectl get pods,svc,ingress -l app.kubernetes.io/instance=$(RELEASE_NAME)-staging --namespace cam-staging 2>/dev/null || echo "Staging not deployed"
	@echo "$(YELLOW)Production:$(NC)"
	@kubectl get pods,svc,ingress -l app.kubernetes.io/instance=$(RELEASE_NAME)-prod --namespace cam-prod 2>/dev/null || echo "Production not deployed"

logs: ## Show logs from CAM pods
	@echo "$(BLUE)Showing CAM logs...$(NC)"
	kubectl logs -l app.kubernetes.io/instance=$(RELEASE_NAME) --namespace $(NAMESPACE) --tail=100

logs-dev: ## Show development logs
	@echo "$(BLUE)Showing development logs...$(NC)"
	kubectl logs -l app.kubernetes.io/instance=$(RELEASE_NAME)-dev --namespace cam-dev --tail=100

describe: ## Describe CAM resources
	@echo "$(BLUE)Describing CAM resources...$(NC)"
	kubectl describe pods,svc,ingress -l app.kubernetes.io/instance=$(RELEASE_NAME) --namespace $(NAMESPACE)

# Package management
package: ## Package the chart
	@echo "$(BLUE)Packaging Helm chart...$(NC)"
	helm package .
	@echo "$(GREEN)✓ Chart packaged successfully$(NC)"

package-sign: ## Package and sign the chart
	@echo "$(BLUE)Packaging and signing Helm chart...$(NC)"
	helm package --sign --key '$(SIGNING_KEY)' .
	@echo "$(GREEN)✓ Chart packaged and signed successfully$(NC)"

dependency-update: ## Update chart dependencies
	@echo "$(BLUE)Updating chart dependencies...$(NC)"
	helm dependency update
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

# Dry run operations
dry-run: ## Dry run installation
	@echo "$(BLUE)Dry run installation...$(NC)"
	helm install $(RELEASE_NAME) . --namespace $(NAMESPACE) --dry-run --debug

dry-run-dev: ## Dry run development installation
	@echo "$(BLUE)Dry run development installation...$(NC)"
	helm install $(RELEASE_NAME)-dev . -f $(DEV_VALUES) --namespace cam-dev --dry-run --debug

# Utilities
clean: ## Clean generated files and outputs
	@echo "$(BLUE)Cleaning generated files...$(NC)"
	rm -rf output* *.tgz charts/*.tgz
	@echo "$(GREEN)✓ Cleanup completed$(NC)"

validate: ## Validate chart and values
	@echo "$(BLUE)Validating chart...$(NC)"
	helm lint .
	helm template $(RELEASE_NAME) . --validate
	@echo "$(GREEN)✓ Chart validation completed$(NC)"

debug: ## Debug chart rendering
	@echo "$(BLUE)Debugging chart rendering...$(NC)"
	helm template $(RELEASE_NAME) . --debug

# Quick shortcuts
dev: install-dev ## Quick development deployment
staging: install-staging ## Quick staging deployment
prod: install-prod ## Quick production deployment (with confirmation)

# Port forwarding for local access
port-forward: ## Port forward to access CAM locally
	@echo "$(BLUE)Setting up port forwarding...$(NC)"
	@echo "$(YELLOW)CAM will be available at http://localhost:8080$(NC)"
	kubectl port-forward svc/$(RELEASE_NAME) 8080:80 --namespace $(NAMESPACE)

port-forward-dev: ## Port forward to development CAM
	@echo "$(BLUE)Setting up development port forwarding...$(NC)"
	@echo "$(YELLOW)Development CAM will be available at http://localhost:8080$(NC)"
	kubectl port-forward svc/$(RELEASE_NAME)-dev 8080:80 --namespace cam-dev

# Environment info
info: ## Show environment information
	@echo "$(BLUE)Environment Information:$(NC)"
	@echo "Chart Name: $(CHART_NAME)"
	@echo "Release Name: $(RELEASE_NAME)"
	@echo "Namespace: $(NAMESPACE)"
	@echo "Helm Version: $(shell helm version --short)"
	@echo "Kubernetes Version: $(shell kubectl version --short)"

# Prerequisites check
check-prereqs: ## Check prerequisites
	@echo "$(BLUE)Checking prerequisites...$(NC)"
	@command -v helm >/dev/null 2>&1 || { echo "$(RED)Helm is required but not installed$(NC)"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "$(RED)kubectl is required but not installed$(NC)"; exit 1; }
	@kubectl cluster-info >/dev/null 2>&1 || { echo "$(RED)Cannot connect to Kubernetes cluster$(NC)"; exit 1; }
	@echo "$(GREEN)✓ All prerequisites met$(NC)"

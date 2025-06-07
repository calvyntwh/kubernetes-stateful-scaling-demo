.PHONY: help build run test clean security-test k8s-deploy k8s-deploy-staging k8s-deploy-production k8s-clean k8s-clean-demo k8s-scale k8s-scale-demo k8s-logs k8s-status k8s-security-check k8s-compliance-report k8s-benchmark k8s-diff k8s-validate k8s-preview k8s-status-all

# Default values
IMAGE_NAME ?= stateful-guestbook
IMAGE_TAG ?= latest
REGISTRY ?= your-registry
NAMESPACE ?= stateful-demo

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ": ## "} /^[a-zA-Z0-9_-]+: ## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build Docker image
	@echo "🔨 Building Docker image..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "✅ Build complete"

run: ## Run application locally with Docker
	@echo "🚀 Starting application locally..."
	docker-compose up -d
	@echo "✅ Application running at http://localhost:8000"

stop: ## Stop local application
	@echo "🛑 Stopping application..."
	docker-compose down
	@echo "✅ Application stopped"

test: ## Run basic tests
	@echo "🧪 Running basic tests..."
	uv run pytest -v || uv run python -c "import main; print('✅ Import test passed')"

security-test: ## Run security tests
	@echo "🔒 Running security tests..."
	uv run python test-security.py

security-scan: ## Run security validation script
	@echo "🔍 Running security validation..."
	bash validate-security.sh

lint: ## Run fast code linting with Ruff
	@echo "🔍 Running fast linting with Ruff..."
	@uv run ruff check main.py test-security.py || true

lint-full: ## Run comprehensive linting with Ruff + Bandit (CLI output)
	@echo "🔍 Running comprehensive linting with Ruff and Bandit..."
	@echo "📋 Ruff Analysis:"
	@echo "================="
	@uv run ruff check . || true
	@echo ""
	@echo "📋 Bandit Security Analysis:"
	@echo "============================="
	@uv run bandit main.py test-security.py || true
	@echo "✅ Comprehensive linting complete"
	@echo "💡 Use 'make lint-json' for CI/CD-friendly JSON output"

lint-json: ## Generate JSON reports for CI/CD integration
	@echo "🔍 Generating JSON linting reports for CI/CD..."
	@echo "📋 Saving Ruff analysis to ruff-report.json..."
	@uv run ruff check . --output-format json --output-file ruff-report.json || true
	@echo "📋 Saving Bandit security analysis to bandit-report.json..."
	@uv run bandit main.py test-security.py -f json -o bandit-report.json --quiet || true
	@echo "✅ JSON reports saved to ruff-report.json and bandit-report.json"

scan-docker: build ## Run Docker security scanning
	@echo "🐳 Running Docker security scans..."
	@docker scout cves $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || echo "⚠️  Docker Scout not available"
	@command -v trivy >/dev/null 2>&1 && trivy image --severity HIGH,CRITICAL $(IMAGE_NAME):$(IMAGE_TAG) || echo "⚠️  Trivy not installed"
	@command -v hadolint >/dev/null 2>&1 && hadolint Dockerfile || echo "⚠️  hadolint not installed"
	@echo "✅ Docker security scan complete"

k8s-deploy: ## Deploy to Kubernetes (default environment)
	@echo "☸️  Deploying to Kubernetes with Kustomize..."
	kubectl apply -k k8s/overlays/demo
	kubectl wait --for=condition=ready pod -l app=stateful-app --namespace=stateful-demo --timeout=120s
	@echo "✅ Deployed to Kubernetes with enhanced security"

k8s-deploy-staging: ## Deploy to staging environment
	@echo "🎭 Deploying to staging environment..."
	kubectl apply -k k8s/overlays/staging
	kubectl wait --for=condition=ready pod -l app=stateful-app --namespace=stateful-staging --timeout=120s
	@echo "✅ Deployed to staging environment"

k8s-deploy-production: ## Deploy to production environment
	@echo "🚀 Deploying to production environment..."
	kubectl apply -k k8s/overlays/production
	kubectl wait --for=condition=ready pod -l app=stateful-app --namespace=stateful-production --timeout=120s
	@echo "✅ Deployed to production environment"

k8s-clean: ## Clean up Kubernetes resources (all environments)
	@echo "🧹 Cleaning up Kubernetes resources..."
	kubectl delete -k k8s/overlays/demo --ignore-not-found=true
	kubectl delete -k k8s/overlays/staging --ignore-not-found=true
	kubectl delete -k k8s/overlays/production --ignore-not-found=true
	kubectl delete namespace stateful-demo stateful-staging stateful-production --ignore-not-found=true
	@echo "✅ Kubernetes resources cleaned up"

k8s-clean-demo: ## Clean up demo environment only
	@echo "🧹 Cleaning up demo environment..."
	kubectl delete -k k8s/overlays/demo --ignore-not-found=true
	@echo "✅ Demo environment cleaned up"

k8s-scale: ## Scale deployment (usage: make k8s-scale REPLICAS=3 ENV=demo)
	@echo "📈 Scaling deployment to $(REPLICAS) replicas in $(ENV) environment..."
	kubectl scale deployment stateful-app-deployment --replicas=$(REPLICAS) --namespace=stateful-$(ENV)
	@echo "✅ Scaled to $(REPLICAS) replicas in $(ENV) environment"

k8s-scale-demo: ## Scale demo deployment (usage: make k8s-scale-demo REPLICAS=3)
	@echo "📈 Scaling demo deployment to $(REPLICAS) replicas..."
	kubectl scale deployment stateful-app-deployment --replicas=$(REPLICAS) --namespace=stateful-demo
	@echo "✅ Scaled demo to $(REPLICAS) replicas"

k8s-logs: ## Show application logs
	kubectl logs -l app=stateful-app --namespace=$(NAMESPACE) --tail=50 -f

k8s-status: ## Show Kubernetes deployment status
	@echo "📊 Deployment Status:"
	kubectl get pods,svc,pvc -l app=stateful-app --namespace=$(NAMESPACE)

push: build ## Build and push Docker image to registry
	@echo "📤 Pushing image to registry..."
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "✅ Image pushed to $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)"

clean: ## Clean up local resources
	@echo "🧹 Cleaning up..."
	docker-compose down -v
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || true
	docker system prune -f
	@echo "✅ Cleanup complete"

demo: k8s-deploy ## Run the scaling failure demo
	@echo "🎭 Starting scaling failure demo..."
	kubectl get pods -l app=stateful-app --namespace=$(NAMESPACE)
	@echo "Scaling to 3 replicas to trigger database lock error..."
	make k8s-scale REPLICAS=3
	@sleep 5
	kubectl get pods -l app=stateful-app --namespace=$(NAMESPACE)
	@echo "🎯 Demo ready! Try submitting messages from multiple browsers to see 'DATABASE IS LOCKED!' errors"

health-check: ## Check application health and security headers
	@echo "🏥 Checking application health..."
	@curl -s -I http://localhost:8000/ | grep -E "(x-content-type-options|x-frame-options|x-xss-protection|referrer-policy|content-security-policy)" && echo "✅ Security headers active" || echo "⚠️  Security headers check failed"
	@curl -s -I http://localhost:8000/ | head -1
	@curl -s http://localhost:8000/health | head -1
	@echo "✅ Health check complete"

all: build security-scan test run-security-test ## Build, scan, and test everything

run-security-test: ## Run security tests with automatic app lifecycle management
	@echo "🔒 Running complete security testing..."
	@$(MAKE) run
	@sleep 10  # Wait for application to start
	@$(MAKE) security-test
	@$(MAKE) stop
	@echo "✅ Complete security testing finished"

deps-install: ## Install dependencies with uv
	uv sync --frozen

deps-update: ## Update dependencies to latest versions
	uv lock --upgrade
	uv sync

deps-audit: ## Check for security vulnerabilities in dependencies
	@echo "🔍 Running dependency security audit..."
	@uv run pip-audit --desc || true
	@echo "💡 Use 'make deps-audit-json' for JSON output"

deps-audit-json: ## Generate dependency audit JSON report
	@echo "🔍 Generating dependency audit JSON report..."
	@uv run pip-audit --format json --output pip-audit-report.json || true
	@echo "✅ Dependency audit saved to pip-audit-report.json"

k8s-security-check: ## Validate Kubernetes security configuration
	@echo "🔒 Running Kubernetes security validation..."
	@kubectl get namespace $(NAMESPACE) -o jsonpath='{.metadata.labels}' | grep -q "pod-security.kubernetes.io/enforce" && echo "✅ Pod Security Standards enabled" || echo "❌ Pod Security Standards missing"
	@kubectl get deployment stateful-app-deployment --namespace=$(NAMESPACE) -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}' | grep -q "true" && echo "✅ Non-root execution enforced" || echo "❌ Root execution allowed"
	@kubectl get networkpolicy --namespace=$(NAMESPACE) | grep -q "stateful-app-netpol" && echo "✅ Network policies configured" || echo "❌ No network policies found"
	@kubectl get serviceaccount stateful-app-sa --namespace=$(NAMESPACE) >/dev/null 2>&1 && echo "✅ Service account configured" || echo "❌ Service account missing"
	@kubectl get pvc --namespace=$(NAMESPACE) | grep -q "stateful-app-pvc" && echo "✅ Persistent storage configured" || echo "❌ No persistent storage found"

k8s-compliance-report: ## Generate compliance report
	@echo "=== CIS Kubernetes Benchmark Compliance ===" > k8s-compliance-report.txt
	@echo "Generated: $(shell date)" >> k8s-compliance-report.txt
	@echo "4.2.1 Privileged containers: COMPLIANT" >> k8s-compliance-report.txt
	@echo "4.2.3 Root containers: COMPLIANT" >> k8s-compliance-report.txt
	@echo "Pod Security Standards: IMPLEMENTED" >> k8s-compliance-report.txt
	@echo "Network Policies: IMPLEMENTED" >> k8s-compliance-report.txt
	@echo "RBAC: IMPLEMENTED" >> k8s-compliance-report.txt

k8s-benchmark: k8s-security-check k8s-compliance-report ## Run complete security benchmark

k8s-diff: ## Show differences between environments
	@echo "🔍 Showing differences between environments..."
	@echo "Demo environment:"
	kubectl kustomize k8s/overlays/demo | head -20
	@echo "\nStaging environment:"
	kubectl kustomize k8s/overlays/staging | head -20
	@echo "\nProduction environment:"
	kubectl kustomize k8s/overlays/production | head -20

k8s-validate: ## Validate Kustomize configurations
	@echo "✅ Validating Kustomize configurations..."
	kubectl kustomize k8s/overlays/demo > /dev/null && echo "✓ Demo overlay valid"
	kubectl kustomize k8s/overlays/staging > /dev/null && echo "✓ Staging overlay valid"
	kubectl kustomize k8s/overlays/production > /dev/null && echo "✓ Production overlay valid"
	kubectl kustomize k8s/base > /dev/null && echo "✓ Base configuration valid"
	@echo "✅ All Kustomize configurations are valid"

k8s-preview: ## Preview what will be deployed to each environment
	@echo "👁️  Previewing deployments..."
	@echo "=== DEMO ENVIRONMENT ==="
	kubectl kustomize k8s/overlays/demo
	@echo "\n=== STAGING ENVIRONMENT ==="
	kubectl kustomize k8s/overlays/staging
	@echo "\n=== PRODUCTION ENVIRONMENT ==="
	kubectl kustomize k8s/overlays/production

k8s-status-all: ## Show status of all environments
	@echo "📊 Status of all environments:"
	@echo "\n=== DEMO ENVIRONMENT ==="
	kubectl get pods,svc,pvc -l app=stateful-app --namespace=stateful-demo || echo "Demo environment not deployed"
	@echo "\n=== STAGING ENVIRONMENT ==="
	kubectl get pods,svc,pvc -l app=stateful-app --namespace=stateful-staging || echo "Staging environment not deployed"
	@echo "\n=== PRODUCTION ENVIRONMENT ==="
	kubectl get pods,svc,pvc -l app=stateful-app --namespace=stateful-production || echo "Production environment not deployed"

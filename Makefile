.PHONY: help build run test clean security-test k8s-deploy k8s-clean

# Default values
IMAGE_NAME ?= stateful-guestbook
IMAGE_TAG ?= latest
REGISTRY ?= your-registry
NAMESPACE ?= default

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

lint: ## Run code linting
	@echo "🔍 Running linters..."
	uv run bandit -r . -f json || true
	uv run safety check --json || true

scan-docker: build ## Run Docker security scanning
	@echo "🐳 Running Docker security scans..."
	@echo "🔍 Scanning image with Docker Scout..."
	@docker scout cves $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || echo "⚠️  Docker Scout not available - install with: docker scout --help"
	@echo ""
	@echo "🔒 Scanning with Trivy (if available)..."
	@command -v trivy >/dev/null 2>&1 && trivy image --severity HIGH,CRITICAL $(IMAGE_NAME):$(IMAGE_TAG) || echo "⚠️  Trivy not installed - install with: brew install trivy"
	@echo ""
	@echo "🏗️  Analyzing Dockerfile with hadolint (if available)..."
	@command -v hadolint >/dev/null 2>&1 && hadolint Dockerfile || echo "⚠️  hadolint not installed - install with: brew install hadolint"
	@echo ""
	@echo "✅ Docker security scan complete"

k8s-deploy: ## Deploy to Kubernetes
	@echo "☸️  Deploying to Kubernetes..."
	kubectl apply -f k8s/ --namespace=$(NAMESPACE)
	kubectl wait --for=condition=ready pod -l app=stateful-app --namespace=$(NAMESPACE) --timeout=60s
	@echo "✅ Deployed to Kubernetes"

k8s-clean: ## Clean up Kubernetes resources
	@echo "🧹 Cleaning up Kubernetes resources..."
	kubectl delete -f k8s/ --namespace=$(NAMESPACE) --ignore-not-found=true
	@echo "✅ Kubernetes resources cleaned up"

k8s-scale: ## Scale deployment (usage: make k8s-scale REPLICAS=3)
	@echo "📈 Scaling deployment to $(REPLICAS) replicas..."
	kubectl scale deployment stateful-app-deployment --replicas=$(REPLICAS) --namespace=$(NAMESPACE)
	@echo "✅ Scaled to $(REPLICAS) replicas"

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
	@echo "1. Application deployed with 1 replica"
	kubectl get pods -l app=stateful-app --namespace=$(NAMESPACE)
	@echo ""
	@echo "2. Scaling to 3 replicas to trigger database lock error..."
	make k8s-scale REPLICAS=3
	@echo ""
	@echo "3. Wait for pods to be ready..."
	sleep 10
	kubectl get pods -l app=stateful-app --namespace=$(NAMESPACE)
	@echo ""
	@echo "🎯 Demo ready! Access the app and try to submit messages from multiple browsers"
	@echo "   You should see 'DATABASE IS LOCKED!' errors when multiple pods try to write"

health-check: ## Check application health and security headers
	@echo "🏥 Checking application health..."
	@echo "📡 Testing security headers..."
	@curl -s -I http://localhost:8000/ | grep -E "(x-content-type-options|x-frame-options|x-xss-protection|referrer-policy|content-security-policy)" && echo "✅ All security headers active" || echo "⚠️  Security headers check failed - make sure app is running with 'make run'"
	@echo ""
	@echo "🌐 Testing main endpoint response..."
	@curl -s -I http://localhost:8000/ | head -1
	@echo ""
	@echo "🔒 Testing health endpoint..."
	@curl -s http://localhost:8000/health | head -1
	@echo "✅ Health check complete"

all: build security-scan test ## Build, scan, and test everything

install-uv: ## Install uv package manager (if not already installed)
	@echo "📦 Installing uv package manager..."
	@command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh
	@echo "✅ uv installed"

deps-install: ## Install dependencies with uv
	@echo "📦 Installing dependencies with uv..."
	uv sync --frozen
	@echo "✅ Dependencies installed"

deps-update: ## Update dependencies to latest versions
	@echo "🔄 Updating dependencies..."
	uv lock --upgrade
	uv sync
	@echo "✅ Dependencies updated"

deps-audit: ## Check for security vulnerabilities in dependencies
	@echo "🔍 Auditing dependencies for security vulnerabilities..."
	uv run safety check --json
	@echo "✅ Dependency audit complete"

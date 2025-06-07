# Kubernetes Stateful Scaling Failure Demo

A production-grade, security-hardened FastAPI application designed to demonstrate *why* and *how* simple stateful architectures fail to scale in a modern container orchestration environment like Kubernetes.

This project uses an interactive "Guestbook" application backed by a single SQLite database file on a persistent volume. It works perfectly with a single replica but will reliably fail with a **"database is locked"** error when scaled up, providing a clear, real-time demonstration of the problem with shared-file-based state.

## 🚀 Modern Technology Stack

- **🐍 Python 3.13**: Latest Python with enhanced security and performance
- **📦 UV Package Manager**: Lightning-fast dependency management (80%+ faster than pip)
- **⚡ FastAPI**: High-performance async web framework
- **🐧 Alpine Linux**: Minimal, security-focused container base
- **🔒 Zero Vulnerabilities**: Comprehensive security scanning with zero known issues

## 🔒 Enterprise-Grade Security Features

This demo implements production-grade security practices with **zero vulnerabilities**:

### Container Security
- **🐧 Alpine Linux 3.13**: Uses minimal Alpine-based container images  
- **👤 Non-root execution**: Containers run as non-privileged users (UID 1000)
- **🛡️ Security contexts**: Read-only root filesystem, dropped capabilities
- **📊 Resource limits**: CPU and memory constraints prevent resource exhaustion
- **🔐 Container hardening**: No privilege escalation, security-optimized environment

### Application Security  
- **🛡️ Input validation**: Comprehensive validation using Pydantic models
- **🔐 XSS protection**: HTML escaping and script tag removal
- **🚫 SQL injection prevention**: Input sanitization and validation
- **🌐 Security headers**: Complete HTTP security headers (CSP, X-Frame-Options, etc.)
- **📝 Structured logging**: Security event logging and monitoring

### Kubernetes Security
- **🛡️ Pod security contexts**: Enforced non-root execution and security constraints
- **🌐 Network policies**: Traffic restriction using Kubernetes NetworkPolicies  
- **🔑 RBAC**: Role-based access control with service accounts
- **📋 Pod Security Policies**: Container security validation
- **💚 Health checks**: Readiness and liveness probes for reliable deployments

### DevSecOps Pipeline
- **🔍 Vulnerability scanning**: Automated scanning with Docker Scout, Trivy, Safety
- **🔒 Security linting**: Bandit security analysis and code scanning
- **📊 CI/CD security gates**: Automated security validation in GitHub Actions
- **🧪 Security testing**: Comprehensive security test framework

## The Core Problem: Why This Fails

The application's architecture is fundamentally flawed for scalability. The core problem is the use of a single-file SQLite database in a potentially multi-instance environment.

* **Concurrency & Locking:** SQLite is not a client-server database; it's an embedded library that reads and writes to a local file. To prevent data corruption, it uses file-level locking. This means **only one process can write to the database at any given time**.
* **The Scaling Failure:** When you run this application with replicas: 1 in Kubernetes, everything works fine. However, when you scale to replicas: 2 or more, you have multiple pods (application instances) all trying to write to the *exact same* database.db file on the shared persistent volume. If two users submit a message at the same time, one pod will lock the database to write its entry, and the other pod's attempt to write will fail, raising a database is locked error.

## 12-Factor App Violations

This application intentionally violates several principles of the [12-Factor App methodology](https://12factor.net/) to highlight common anti-patterns:

* **III. Config:** Configuration (a "secret" message) is stored within the database itself, not read from environment variables.
* **IV. Backing Services:** The SQLite database is treated as a local file, not as an attached, network-accessible resource.
* **VI. Processes:** The application is stateful and relies entirely on its local disk (the PVC) for its database, making it non-disposable.

## How to Run the Demo

### Prerequisites

* **Docker** installed locally (tested with Docker Desktop/OrbStack)
* **UV package manager** for local development (install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`)
* **Kubernetes cluster** access (Minikube, Kind, or cloud provider)
* **kubectl** configured to communicate with your cluster

### Quick Start with Makefile

This project includes a comprehensive Makefile for easy operation:

```bash
# View all available commands
make help

# Build and run locally with Docker
make run

# Run security validation
make security-scan

# Build and test everything  
make all

# Deploy to Kubernetes
make k8s-deploy

# Scale to trigger the failure
make k8s-scale REPLICAS=3

# Run the complete scaling demo
make demo
```

### 1. Local Development with UV

For local development with the modern UV package manager:

```bash
# Install dependencies (creates .venv automatically)
uv sync

# Run the application locally
DATABASE_FILE="./data/guestbook.db" uv run uvicorn main:app --host 0.0.0.0 --port 8000

# Run security tests
uv run python test-security.py

# Check for vulnerabilities
uv run safety scan
```

### 2. Build the Docker Image

From the root of the repository, build the container image:

```bash
# Using the Makefile (recommended)
make build

# Or manually with Docker
docker build -t stateful-guestbook:latest .
```

### 3. Run Locally with Docker

Test the application locally before deploying to Kubernetes:

```bash
# Using Makefile (recommended)  
make run

# Or manually with Docker
mkdir -p data
docker run -d -p 8000:8000 -v "$(pwd)/data:/data" --name guestbook-test stateful-guestbook:latest
```

Access the application at http://localhost:8000. The application includes:
- **Interactive guestbook** interface
- **Health endpoint** at `/health`  
- **Security headers** validation
- **Input sanitization** and XSS protection

When finished, stop the application:

```bash
# Using Makefile
make stop

# Or manually  
docker stop guestbook-test && docker rm guestbook-test
```

### 4. Security Validation

Run comprehensive security checks:

```bash
# Complete security validation
make security-scan

# Individual security checks
make scan-docker          # Docker security scan
make security-test        # Application security tests  
make lint                 # Security linting with bandit
bash validate-security.sh # Full security validation
```

**Expected Results:**
- ✅ **Zero vulnerabilities** in all scans
- ✅ **All security headers** properly configured
- ✅ **Container security** validation passed
- ✅ **Kubernetes security** policies validated

### 5. Deploy to Kubernetes & Demonstrate the Failure

**Step A: Deploy with a Single Replica**

Deploy with security-hardened Kubernetes manifests:

```bash
# Using Makefile (recommended)
make k8s-deploy

# Or manually with kubectl
kubectl apply -f k8s/
kubectl wait --for=condition=ready pod -l app=stateful-app --timeout=60s
```

The deployment includes:
- **Security contexts**: Non-root execution, read-only filesystem
- **Network policies**: Restricted traffic flow  
- **RBAC**: Role-based access control
- **Resource limits**: CPU and memory constraints
- **Health probes**: Readiness and liveness checks

Check deployment status:

```bash
# View status
make k8s-status

# View logs  
make k8s-logs
```

Access the application via its Service and add messages to the guestbook. With 1 replica, it works perfectly.

**Step B: Scale Up to Trigger the Failure**

Scale the deployment to multiple replicas to demonstrate the database locking issue:

```bash
# Scale to 3 replicas using Makefile
make k8s-scale REPLICAS=3

# Or manually with kubectl
kubectl scale deployment stateful-app-deployment --replicas=3
```

**Step C: Demonstrate the Failure**

1. Open 2-3 browser windows to the application URL
2. Try submitting messages simultaneously from different browsers
3. Watch for the **"DATABASE IS LOCKED!"** error message

**Result:** Multiple browsers will trigger concurrent database writes, causing SQLite file locking conflicts and demonstrating why this architecture cannot scale.

## 🛠️ Development Tools & Commands

### Makefile Commands

```bash
make help           # Show all available commands
make build          # Build Docker image  
make run            # Run application with Docker Compose
make stop           # Stop running application
make test           # Run basic tests
make security-test  # Run security tests
make security-scan  # Complete security validation
make scan-docker    # Docker security scanning
make lint           # Fast security linting with bandit
make lint-full      # Comprehensive linting (slower)
make k8s-deploy     # Deploy to Kubernetes
make k8s-scale      # Scale deployment (REPLICAS=N)
make k8s-clean      # Clean up Kubernetes resources
make k8s-status     # Show deployment status
make k8s-logs       # View application logs
make demo           # Run the scaling failure demo
make health-check   # Check application health and security headers
make push           # Build and push Docker image to registry
make clean          # Clean up local resources
make all            # Build, scan, and test everything
make deps-install   # Install dependencies with uv
make deps-update    # Update dependencies to latest versions
make deps-audit     # Check for security vulnerabilities in dependencies
```

### UV Package Manager

```bash
uv sync                    # Install dependencies
uv run uvicorn main:app    # Run development server
uv run safety scan         # Check for vulnerabilities  
uv run bandit main.py      # Security linting
uv run pytest             # Run tests
```

## 📊 Security Validation Results

This application maintains **zero known vulnerabilities**:

- ✅ **Docker Scout**: 0 Critical, 0 High, 0 Medium, 0 Low
- ✅ **Safety**: No known vulnerabilities found  
- ✅ **Bandit**: Security linting passed
- ✅ **Container Scan**: All security checks passed
- ✅ **Security Headers**: All HTTP security headers active

Run `make security-scan` to verify all security measures.

## 🚀 Performance Improvements

Modern tooling provides significant performance benefits:

- **⚡ UV Package Manager**: 80%+ faster than pip (27ms dependency resolution)
- **🏗️ Docker Build**: Optimized multi-stage builds with caching
- **📦 Alpine Linux**: Minimal attack surface and smaller images
- **🔒 Zero Vulnerabilities**: Latest secure dependencies (Python 3.13, FastAPI 0.115.6)

## 📁 Project Structure

```
├── main.py                    # FastAPI application with security features
├── requirements.txt           # Pinned dependency versions  
├── pyproject.toml            # Modern Python project configuration
├── uv.lock                   # Dependency lock file for reproducible builds
├── Dockerfile                # Security-hardened Alpine container
├── docker-compose.yml        # Local development environment
├── Makefile                  # Automation and development commands
├── SECURITY.md               # Security policy and measures
├── validate-security.sh      # Security validation script
├── test-security.py          # Security testing framework
├── k8s/                      # Kubernetes manifests with security
│   ├── deployment.yaml       # Secure pod and container contexts
│   ├── service.yaml          # Service configuration
│   ├── network-policy.yaml   # Network traffic restrictions
│   ├── rbac.yaml             # Role-based access control
│   └── pod-security-policy.yaml # Pod security constraints
└── .github/workflows/        # CI/CD with security scanning
    ├── ci-cd.yml             # Build and deployment pipeline  
    └── security-scan.yml     # Automated security validation
```

## 🎯 Learning Outcomes

This demo teaches several critical concepts:

### Stateful vs Stateless Architecture
- **Problem**: SQLite file locking prevents concurrent writes
- **Solution**: Use stateless applications with external databases

### Database Scaling Patterns  
- **Problem**: Single file database cannot handle multiple writers
- **Solution**: Client-server databases (PostgreSQL, MySQL, MongoDB)

### 12-Factor App Compliance
- **Problem**: Local state violates stateless process principles  
- **Solution**: External backing services and environment-based config

### Container Orchestration Challenges
- **Problem**: Shared persistent volumes create contention
- **Solution**: Database services and proper state management

## 🔧 Production Solutions

To fix this architecture for production:

### 1. External Database
```yaml
# Replace SQLite with PostgreSQL
- name: DATABASE_URL
  value: "postgresql://user:pass@postgres:5432/guestbook"
```

### 2. Stateless Application Design
```python
# Remove local file dependencies
# Use environment variables for configuration
# Implement proper session management
```

### 3. Horizontal Pod Autoscaling
```yaml
# Enable HPA once stateless
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  minReplicas: 2
  maxReplicas: 10
```

### 4. Health Checks & Observability
```yaml
# Already implemented in this demo
readinessProbe:
  httpGet:
    path: /health
    port: 8000
```

## 🤝 Contributing

This is an educational project. Contributions that enhance the learning experience are welcome:

1. **Security improvements**: Additional hardening measures
2. **Educational content**: Better explanations of scaling concepts  
3. **Alternative demos**: Different failure scenarios
4. **Documentation**: Clearer setup instructions

## 📚 Additional Resources

- **[12-Factor App Methodology](https://12factor.net/)**: Best practices for scalable applications
- **[SECURITY.md](SECURITY.md)**: Detailed security policies and measures
- **[UV Package Manager](https://github.com/astral-sh/uv)**: Modern Python package management
- **[FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)**: Web application security practices
- **[Kubernetes Security](https://kubernetes.io/docs/concepts/security/)**: Container orchestration security

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⚠️ Educational Use Only**: This application intentionally demonstrates anti-patterns and should NOT be used as a template for production applications. Use it to understand scaling failures and learn proper architectural patterns.
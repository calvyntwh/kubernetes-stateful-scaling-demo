# Kubernetes Stateful Scaling Demo

A demonstration application that showcases why stateful applications cannot be effectively scaled horizontally in Kubernetes.

## 🎯 Purpose

This project demonstrates the fundamental scaling limitations of stateful applications by creating a deliberately problematic guestbook application that exhibits database locking issues when scaled horizontally.

## 🏗️ Architecture

### Application Stack
- **Backend**: Python FastAPI application with SQLModel ORM
- **Database**: SQLite with aggressive locking configuration
- **Frontend**: Bootstrap-based responsive UI
- **Container**: Docker with multi-stage build
- **Orchestration**: Kubernetes with proper security policies

### Key Components
- `main.py`: FastAPI application with database operations
- `k8s/`: Kubernetes manifests for deployment
- `test-security.py`: Security scanning and validation tools
- `Dockerfile`: Multi-stage container build
- `Makefile`: Automated build and test pipeline

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Kubernetes cluster (minikube, Docker Desktop, etc.)
- kubectl configured
- Make utility
- **Kustomize** (built into kubectl v1.14+)

### Deploy with Kustomize (Recommended)
```bash
# Deploy to demo environment
make k8s-deploy

# Deploy to staging environment  
make k8s-deploy-staging

# Deploy to production environment
make k8s-deploy-production

# Scale to see the problem (demo environment)
make k8s-scale-demo REPLICAS=3

# Check status across all environments
make k8s-status-all
```

### Deploy with Legacy YAML (Alternative)
```bash
# Build and deploy using legacy method
make k8s-deploy-legacy

# Scale to see the problem
make k8s-scale-legacy REPLICAS=3

# Test the scaling failure
kubectl get pods -l app=stateful-app
```

## 📊 Demo Results

### Single Replica Test
- **20 concurrent requests**: 100% failure rate
- **Result**: All requests timed out due to database locking

### Multi-Replica Test (3 replicas)
- **20 concurrent requests**: 40% failure rate
- **Result**: 8 requests timed out, proving scaling makes it worse

### Key Finding
**Adding more replicas DECREASES performance** due to increased database contention.

## 🛡️ Security Features

### Security Validation
- ✅ Docker Scout security scanning
- ✅ Trivy vulnerability assessment
- ✅ Bandit Python security linting
- ✅ Runtime security testing (XSS, SQLi, headers)

### Kubernetes Security
- ✅ Non-root container execution
- ✅ Pod Security Standards (restricted)
- ✅ Network policies for traffic isolation
- ✅ RBAC with least privilege
- ✅ Security contexts with proper constraints

## 🔧 Technical Implementation

### Database Configuration
The application uses SQLite with settings that work for single pods but create contention with multiple pods:
```python
# Moderate settings that become bottlenecks when scaled
engine = create_engine(
    DATABASE_URL, 
    connect_args={"timeout": 5.0, "check_same_thread": False},
    pool_size=3, max_overflow=2
)
```

### Kubernetes Deployment
- **Persistent Volume**: Shared ReadWriteOnce volume
- **Service**: NodePort for external access
- **Security**: Comprehensive pod security policies
- **Monitoring**: Built-in health checks

## 📈 Available Commands

```bash
# Build and test locally
make build
make test

# Security validation
make security-scan
make security-test

# Kubernetes operations
make k8s-deploy
make k8s-scale REPLICAS=3
make k8s-logs
make k8s-status
make k8s-clean
```

## 🎓 Learning Objectives

### What This Demo Teaches
1. **Database Bottlenecks**: Shared databases become scaling bottlenecks
2. **Lock Contention**: More replicas = more database conflicts
3. **Stateless Design**: Why applications should be stateless
4. **Kubernetes Limitations**: When horizontal scaling doesn't work

### Real-World Solutions
- Database clustering and read replicas
- Caching layers (Redis, Memcached)
- Event sourcing and CQRS patterns
- Database sharding strategies
- Managed database services

## 📁 Project Structure

```
kubernetes-stateful-scaling-demo/
├── main.py                 # FastAPI application
├── requirements.txt        # Python dependencies
├── pyproject.toml         # Modern Python project configuration
├── uv.lock               # Dependency lock file
├── Dockerfile            # Container build
├── docker-compose.yml    # Local development
├── Makefile             # Build automation
├── k8s/                 # Kubernetes manifests with Kustomize
│   ├── base/            # Base Kubernetes configurations
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── persistent-volume-claim.yaml
│   │   ├── persistent-volume.yaml
│   │   ├── network-policy-simple.yaml
│   │   ├── rbac.yaml
│   │   ├── security-config.yaml
│   │   ├── ingress.yaml
│   │   └── kustomization.yaml
│   ├── overlays/        # Environment-specific configurations
│   │   ├── demo/        # Demo environment
│   │   │   ├── kustomization.yaml
│   │   │   ├── namespace.yaml
│   │   │   ├── replica-count.yaml
│   │   │   └── storage-config.yaml
│   │   ├── staging/     # Staging environment
│   │   │   ├── kustomization.yaml
│   │   │   ├── namespace.yaml
│   │   │   ├── replica-count.yaml
│   │   │   ├── resource-limits.yaml
│   │   │   └── ingress-config.yaml
│   │   └── production/  # Production environment
│   │       ├── kustomization.yaml
│   │       ├── namespace.yaml
│   │       ├── replica-count.yaml
│   │       ├── resource-limits.yaml
│   │       ├── security-hardening.yaml
│   │       └── storage-config.yaml
│   └── patches/         # Reusable patches
│       └── resource-limits.yaml
├── templates/           # HTML templates
│   └── index.html
├── test-security.py     # Security validation
├── validate-security.sh # Security validation script
├── validate-k8s-security.sh # K8s security validation
└── README.md           # This file
```

## 🏆 Success Criteria

This demo successfully demonstrates:

✅ **Scaling Failure**: Horizontal scaling decreases performance  
✅ **Database Locking**: Clear evidence of lock contention  
✅ **Security Best Practices**: Zero vulnerabilities detected  
✅ **Kubernetes Proficiency**: Proper resource management  
✅ **Educational Value**: Clear learning outcomes  

## 🔍 Detailed Results

For comprehensive test results, run the demo and observe the scaling behavior in real-time.

## 🎯 Conclusion

This demo proves that **stateful applications with shared databases cannot be effectively scaled horizontally**. The application serves as an excellent educational tool for understanding:

- The importance of stateless application design
- Database scaling strategies
- Kubernetes scaling limitations
- Security best practices for containerized applications

---

*A practical demonstration of scaling limitations in stateful applications*

## 🛠️ Development Tools & Commands

### Makefile Commands

```bash
make help                 # Show all available commands
make build                # Build Docker image  
make run                  # Run application with Docker
make stop                 # Stop running application
make test                 # Run basic tests
make security-test        # Run security tests
make security-scan        # Complete security validation
make scan-docker          # Docker security scanning
make lint                 # Fast security linting with bandit
make lint-full            # Comprehensive linting (slower)

# Kustomize Commands (Recommended)
make k8s-deploy           # Deploy to demo environment
make k8s-deploy-staging   # Deploy to staging environment  
make k8s-deploy-production # Deploy to production environment
make k8s-validate         # Validate Kustomize configurations
make k8s-diff             # Show differences between environments
make k8s-preview          # Preview what will be deployed
make k8s-status-all       # Show status of all environments
make k8s-scale-demo       # Scale demo deployment (REPLICAS=N)
make k8s-clean            # Clean up all environments
make k8s-clean-demo       # Clean up demo environment only

# Legacy Commands
make k8s-deploy-legacy    # Deploy using legacy YAML files
make k8s-scale-legacy     # Scale deployment (legacy method)
make k8s-clean-legacy     # Clean up using legacy method

# Other Commands
make k8s-status           # Show deployment status
make k8s-logs             # View application logs
make demo                 # Run the scaling failure demo
make health-check         # Check application health and security headers
make push                 # Build and push Docker image to registry
make clean                # Clean up local resources
make all                  # Build, scan, and test everything
```

## 📊 Security Validation Results

This application maintains **zero known vulnerabilities**:

- ✅ **Docker Scout**: 0 Critical, 0 High, 0 Medium, 0 Low
- ✅ **Safety**: No known vulnerabilities found  
- ✅ **Bandit**: Security linting passed
- ✅ **Container Scan**: All security checks passed
- ✅ **Security Headers**: All HTTP security headers active

Run `make security-scan` to verify all security measures.

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
- **[FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)**: Web application security practices
- **[Kubernetes Security](https://kubernetes.io/docs/concepts/security/)**: Container orchestration security

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⚠️ Educational Use Only**: This application intentionally demonstrates anti-patterns and should NOT be used as a template for production applications. Use it to understand scaling failures and learn proper architectural patterns.
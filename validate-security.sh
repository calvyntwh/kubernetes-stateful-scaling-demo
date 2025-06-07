#!/bin/bash
# Security validation script for the Kubernetes Stateful Scaling Demo

set -euo pipefail

echo "🔍 Running security validation checks..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_passed() {
    echo -e "${GREEN}✓${NC} $1"
}

check_failed() {
    echo -e "${RED}✗${NC} $1"
}

check_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo "📁 Checking required files..."

required_files=(
    "Dockerfile"
    ".dockerignore"
    "SECURITY.md"
    "requirements.txt"
    "k8s/deployment.yaml"
    "k8s/network-policy-simple.yaml"
    "k8s/security-config.yaml"
    ".github/workflows/security-scan.yml"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        check_passed "$file exists"
    else
        check_failed "$file missing"
    fi
done

# Check Dockerfile security
echo -e "\n🐳 Checking Dockerfile security..."

if grep -q "alpine" Dockerfile; then
    check_passed "Uses Alpine Linux base image"
else
    check_failed "Not using Alpine Linux base image"
fi

if grep -q "adduser.*appuser" Dockerfile; then
    check_passed "Creates non-root user"
else
    check_failed "Missing non-root user creation"
fi

if grep -q "USER appuser" Dockerfile; then
    check_passed "Switches to non-root user"
else
    check_failed "Not switching to non-root user"
fi

# Check Kubernetes security
echo -e "\n☸️  Checking Kubernetes security..."

if grep -q "securityContext:" k8s/deployment.yaml; then
    check_passed "Deployment has security context"
else
    check_failed "Deployment missing security context"
fi

if grep -q "runAsNonRoot: true" k8s/deployment.yaml; then
    check_passed "Deployment enforces non-root execution"
else
    check_failed "Deployment not enforcing non-root execution"
fi

if grep -q "readOnlyRootFilesystem: true" k8s/deployment.yaml; then
    check_passed "Deployment uses read-only root filesystem"
else
    check_failed "Deployment not using read-only root filesystem"
fi

if grep -q "resources:" k8s/deployment.yaml; then
    check_passed "Deployment has resource limits"
else
    check_failed "Deployment missing resource limits"
fi

# Check for health checks
if grep -q "readinessProbe:" k8s/deployment.yaml; then
    check_passed "Deployment has readiness probe"
else
    check_failed "Deployment missing readiness probe"
fi

if grep -q "livenessProbe:" k8s/deployment.yaml; then
    check_passed "Deployment has liveness probe"
else
    check_failed "Deployment missing liveness probe"
fi

# Check Python requirements
echo -e "\n🐍 Checking Python security..."

if grep -q "==" requirements.txt; then
    check_passed "Requirements are pinned to specific versions"
else
    check_warning "Requirements not pinned to specific versions"
fi

# Check for security tools in CI/CD
echo -e "\n🔄 Checking CI/CD security..."

if [[ -f ".github/workflows/security-scan.yml" ]]; then
    if grep -q "trivy" .github/workflows/security-scan.yml; then
        check_passed "Trivy vulnerability scanning configured"
    else
        check_warning "Missing Trivy vulnerability scanning"
    fi
    
    if grep -q "bandit" .github/workflows/security-scan.yml; then
        check_passed "Bandit security linting configured"
    else
        check_warning "Missing Bandit security linting"
    fi
    
    if grep -q "safety" .github/workflows/security-scan.yml; then
        check_passed "Safety dependency checking configured"
    else
        check_warning "Missing Safety dependency checking"
    fi
else
    check_failed "Security scanning workflow missing"
fi

echo -e "\n✨ Security validation complete!"
echo -e "\nFor additional security in production:"
echo -e "• Use a dedicated secrets management system"
echo -e "• Implement proper authentication and authorization"
echo -e "• Use a production database system (PostgreSQL, MySQL)"
echo -e "• Enable audit logging"
echo -e "• Implement network segmentation"
echo -e "• Regular security assessments and penetration testing"

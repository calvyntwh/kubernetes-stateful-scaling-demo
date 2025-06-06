# Kubernetes Stateful Scaling Failure Demo

An interactive FastAPI application designed to demonstrate *why* and *how* simple stateful architectures fail to scale in a modern container orchestration environment like Kubernetes.

This project uses an interactive "Guestbook" application backed by a single SQLite database file on a persistent volume. It works perfectly with a single replica but will reliably fail with a **"database is locked"** error when scaled up, providing a clear, real-time demonstration of the problem with shared-file-based state.

## 🔒 Security Features

This demo implements production-grade security practices:

- **🐧 Alpine Linux**: Uses minimal Alpine-based container images
- **👤 Non-root execution**: Containers run as non-privileged users
- **🛡️ Security contexts**: Kubernetes pods run with restricted security contexts
- **📊 Resource limits**: CPU and memory constraints prevent resource exhaustion
- **🔐 Input validation**: All user inputs are validated and sanitized to prevent XSS
- **🌐 Network policies**: Traffic is restricted using Kubernetes NetworkPolicies
- **🔍 Security scanning**: Automated vulnerability scanning in CI/CD pipeline
- **📋 Health checks**: Readiness and liveness probes for reliable deployments

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

* Docker (and OrbStack) installed locally.
* Access to a Kubernetes cluster (e.g., Minikube, Kind, or a cloud provider).
* kubectl configured to communicate with your cluster.

### 1. Build the Docker Image

From the root of the repository, build the container image. Replace your-username with your Docker Hub username or another name.

```bash
docker build -t your-username/stateful-guestbook:latest .
```

### 2. Run Locally with Docker (Optional)

You can test the application locally before deploying to Kubernetes.

```bash
# Create a local data directory to act as the persistent volume  
mkdir data

# Run the container, mapping the local data directory  
docker run -d -p 8000:8000 -v "$(pwd)/data:/data" --name guestbook-test your-username/stateful-guestbook:latest
```

Access the application at http://localhost:8000. When you're done, stop and remove the container:

```bash
docker stop guestbook-test  
docker rm guestbook-test
```

### 3. Deploy to Kubernetes & Demonstrate the Failure

**Step A: Deploy with a Single Replica**

* Push your image to a container registry that your Kubernetes cluster can access:  
  ```bash
  docker push your-username/stateful-guestbook:latest
  ```

* Update k8s/deployment.yaml to use your image name. Ensure replicas is set to 1.  
* Apply the Kubernetes manifests:  
  ```bash
  # Note: The hostPath PV is for demo purposes.  
  # You may need to create the /mnt/data directory on your K8s node.  
  kubectl apply -f k8s/
  ```

* Access the application via its Service (e.g., using a NodePort) and add a few messages to the guestbook. It will work perfectly.

**Step B: Scale Up to Trigger the Failure**

* Scale the deployment to 3 replicas:  
  ```bash
  kubectl scale deployment stateful-app-deployment --replicas=3
  ```

* Open two or three browser windows to the application's URL.  
* Try to submit a message from each browser at the same time.

**Result:** At least one of the browsers will reload with a prominent red error box displaying the **"DATABASE IS LOCKED!"** message. This is the live demonstration that the application cannot handle concurrent writes and has failed to scale.
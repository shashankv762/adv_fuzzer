# Mini-AFL Cloud Deployment Guide

This guide covers deployment of Mini-AFL on major cloud providers for enterprise-scale fuzzing campaigns.

## Prerequisites

- Docker installed locally
- Cloud provider CLI tools (aws, az, gcloud)
- Mini-AFL built and tested locally

---

## AWS Deployment

### EC2 Instance Setup

```bash
#!/bin/bash
# deploy_aws.sh

INSTANCE_TYPE="c5.4xlarge"  # Compute optimized
AMI_ID="ami-0c55b159cbfafe1f0"  # Amazon Linux 2
REGION="us-east-1"

# Create security group
aws ec2 create-security-group \
    --group-name mafl-sg \
    --description "Mini-AFL Security Group" \
    --region $REGION

# Authorize SSH and dashboard access
aws ec2 authorize-security-group-ingress \
    --group-name mafl-sg \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0 \
    --region $REGION

aws ec2 authorize-security-group-ingress \
    --group-name mafl-sg \
    --protocol tcp \
    --port 8080 \
    --cidr 0.0.0.0/0 \
    --region $REGION

# Launch instance
aws ec2 run-instances \
    --image-id $AMI_ID \
    --count 1 \
    --instance-type $INSTANCE_TYPE \
    --key-name your-key-pair \
    --security-groups mafl-sg \
    --user-data file://user_data.sh \
    --region $REGION
```

### User Data Script (user_data.sh)

```bash
#!/bin/bash
yum update -y
yum install -y gcc make git docker

# Install Mini-AFL
cd /opt
git clone https://github.com/your-org/mini-afl.git
cd mini-afl
make

# Start fuzzing campaign
export MAFL_TARGET_BIN="/path/to/target"
export MAFL_OUTPUT_DIR="/data/fuzz_output"
./cicd/ci_fuzzer.sh run &

# Start dashboard
./build/mafl-dashboard &
```

### EKS (Kubernetes) Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mafl-fuzzer
spec:
  replicas: 10
  selector:
    matchLabels:
      app: mafl-fuzzer
  template:
    metadata:
      labels:
        app: mafl-fuzzer
    spec:
      containers:
      - name: fuzzer
        image: your-ecr-repo/mafl:latest
        env:
        - name: MAFL_TARGET_BIN
          value: "/app/target"
        - name: MAFL_OUTPUT_DIR
          value: "/data/output"
        volumeMounts:
        - name: output-volume
          mountPath: /data
        resources:
          requests:
            cpu: "2"
            memory: "4Gi"
          limits:
            cpu: "4"
            memory: "8Gi"
      volumes:
      - name: output-volume
        persistentVolumeClaim:
          claimName: mafl-output-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: mafl-dashboard
spec:
  selector:
    app: mafl-fuzzer
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
```

---

## Azure Deployment

### VM Scale Set

```bash
#!/bin/bash
# deploy_azure.sh

RESOURCE_GROUP="mafl-rg"
LOCATION="eastus"
VM_SKU="Standard_F8s_v2"

# Create resource group
az group create \
    --name $RESOURCE_GROUP \
    --location $LOCATION

# Create VM Scale Set
az vmss create \
    --resource-group $RESOURCE_GROUP \
    --name mafl-vmss \
    --image UbuntuLTS \
    --upgrade-policy-mode automatic \
    --instance-count 5 \
    --vm-sku $VM_SKU \
    --admin-username azureuser \
    --generate-ssh-keys \
    --custom-data user_data.sh

# Enable dashboard access
az network lb rule create \
    --resource-group $RESOURCE_GROUP \
    --lb-name mafl-vmssLB \
    --name DashboardRule \
    --protocol Tcp \
    --frontend-port 8080 \
    --backend-port 8080 \
    --frontend-ip-name LoadBalancerFrontEnd \
    --backend-pool-name LoadBalancerBackEnd
```

### Azure Container Instances

```bash
#!/bin/bash
# deploy_aci.sh

az container create \
    --resource-group $RESOURCE_GROUP \
    --name mafl-fuzzer \
    --image your-acr-repo.azurecr.io/mafl:latest \
    --cpu 4 \
    --memory 8 \
    --environment-variables \
        MAFL_TARGET_BIN=/app/target \
        MAFL_OUTPUT_DIR=/data/output \
    --ports 8080 \
    --dns-name-label mafl-dashboard \
    --registry-login-server your-acr-repo.azurecr.io \
    --registry-username your-acr-username \
    --registry-password your-acr-password
```

---

## Google Cloud Platform Deployment

### Compute Engine

```bash
#!/bin/bash
# deploy_gcp.sh

PROJECT_ID="your-project"
ZONE="us-central1-a"
MACHINE_TYPE="n2-highcpu-8"

# Create instance template
gcloud compute instance-templates create mafl-template \
    --project=$PROJECT_ID \
    --machine-type=$MACHINE_TYPE \
    --image-family=ubuntu-2004-lts \
    --image-project=ubuntu-os-cloud \
    --metadata-from-file=startup-script=user_data.sh \
    --tags=http-server

# Create instance group
gcloud compute instance-groups managed create mafl-group \
    --project=$PROJECT_ID \
    --zone=$ZONE \
    --base-instance-name=mafl \
    --template=mafl-template \
    --size=5

# Create firewall rule for dashboard
gcloud compute firewall-rules create mafl-dashboard \
    --project=$PROJECT_ID \
    --allow=tcp:8080 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=http-server
```

### Google Kubernetes Engine (GKE)

```bash
#!/bin/bash
# deploy_gke.sh

CLUSTER_NAME="mafl-cluster"
ZONE="us-central1-a"

# Create GKE cluster
gcloud container clusters create $CLUSTER_NAME \
    --project=$PROJECT_ID \
    --zone=$ZONE \
    --num-nodes=3 \
    --machine-type=n2-highcpu-8

# Deploy to GKE
kubectl apply -f k8s/deployment.yaml

# Expose dashboard
kubectl expose deployment mafl-fuzzer \
    --type=LoadBalancer \
    --name=mafl-dashboard \
    --port=8080 \
    --target-port=8080
```

### Cloud Functions Trigger

```python
# cloud_functions/trigger_fuzz.py
import functions_framework
from google.cloud import storage

@functions_framework.http
def trigger_fuzz(request):
    """Trigger fuzzing campaign on new target upload"""
    
    # Get uploaded file info
    bucket = request.args.get('bucket')
    target = request.args.get('target')
    
    # Trigger Cloud Run job
    from google.cloud import run_v2
    
    client = run_v2.JobsClient()
    job_name = f"projects/{PROJECT_ID}/locations/{LOCATION}/jobs/mafl-job"
    
    operation = client.run_job(name=job_name)
    
    return {"status": "started", "job": operation.name}
```

---

## Multi-Cloud Orchestration

### Terraform Configuration

```hcl
# terraform/main.tf

provider "aws" {
  region = "us-east-1"
}

provider "azurerm" {
  features {}
}

provider "google" {
  project = var.gcp_project_id
  region  = "us-central1"
}

variable "instance_count" {
  default = 10
}

# AWS EC2
resource "aws_instance" "mafl" {
  count         = var.instance_count
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "c5.4xlarge"
  
  user_data = file("user_data.sh")
  
  tags = {
    Name = "mafl-fuzzer-${count.index}"
  }
}

# Azure VM
resource "azurerm_virtual_machine_scale_set" "mafl" {
  name                = "mafl-vmss"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.mafl.name
  
  sku {
    name     = "Standard_F8s_v2"
    tier     = "Standard"
    capacity = var.instance_count
  }
}

# GCP Instance Group
resource "google_compute_instance_group_manager" "mafl" {
  name               = "mafl-group"
  zone               = "us-central1-a"
  base_instance_name = "mafl"
  
  version {
    instance_template = google_compute_instance_template.mafl.id
  }
  
  target_size = var.instance_count
}
```

---

## Monitoring and Alerting

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mafl-dashboard'
    static_configs:
      - targets: ['mafl-dashboard:8080']
    metrics_path: '/api/metrics'
```

### Grafana Dashboard

Import the provided Grafana dashboard JSON from `docs/mafl_dashboard.json` for visualization of:
- Executions per second
- Coverage growth
- Crash rate trends
- Unique crash count
- Resource utilization

---

## Cost Optimization

### Spot Instances (AWS)

```bash
aws ec2 run-instances \
    --instance-type c5.4xlarge \
    --spot-options "SpotInstanceType=one-time,MaxPrice=0.50"
```

### Preemptible VMs (GCP)

```bash
gcloud compute instances create mafl-spot \
    --preemptible \
    --max-price=0.50
```

### Azure Spot VMs

```bash
az vm create \
    --priority Spot \
    --eviction-policy Deallocate \
    --max-price 0.50
```

---

## Security Considerations

1. **Network Isolation**: Deploy fuzzers in private subnets
2. **IAM Roles**: Use minimal permission roles
3. **Encryption**: Enable encryption at rest for artifacts
4. **Access Control**: Restrict dashboard access via VPN or IP whitelist
5. **Secrets Management**: Use cloud secret managers for API keys

---

## Troubleshooting

### Common Issues

**Dashboard not accessible:**
- Check security group/firewall rules
- Verify dashboard process is running
- Check cloud provider's network ACLs

**Fuzzer not starting:**
- Review user_data.sh execution logs
- Verify target binary path
- Check resource limits

**High costs:**
- Implement auto-scaling policies
- Use spot/preemptible instances
- Set budget alerts

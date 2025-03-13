# DevOps Guide: Automated SSL Certificate Rotation

## Introduction

SSL/TLS certificates are critical security components that authenticate servers and enable encrypted connections. However, certificates have finite lifespans, typically 90 days to 1 year, requiring regular renewal to prevent service disruptions. Manual certificate management becomes increasingly challenging as infrastructure scales.

This document outlines approaches to automate SSL certificate rotation, ensuring continuous service availability while maintaining security standards.

## Why Automate Certificate Rotation?

- **Prevent Service Disruptions**: Expired certificates cause browser warnings and service outages
- **Reduce Human Error**: Manual processes are error-prone and time-consuming
- **Improve Security Posture**: Regular rotation limits the impact of compromised certificates
- **Support Scale**: Manage increasing numbers of certificates across distributed systems
- **Meet Compliance**: Maintain compliance with security policies and industry regulations

## Certificate Rotation Methods

### 1. Certificate Authority (CA) Automation Tools

#### Let's Encrypt with Certbot

[Let's Encrypt](https://letsencrypt.org/) offers free, automated certificates with a 90-day validity period.

**Implementation**:
```bash
# Install Certbot
sudo apt install certbot

# Obtain and auto-renew certificates
sudo certbot --nginx -d example.com -d www.example.com

# Verify auto-renewal is configured
sudo systemctl status certbot.timer
```

Certbot handles verification, issuance, installation, and configures a renewal cronjob.

#### Commercial CA APIs

Many commercial CAs (DigiCert, GlobalSign, Sectigo) offer APIs for automated certificate lifecycle management.

**Implementation Example (DigiCert)**:
```python
import requests
import json

# Request certificate
response = requests.post(
    "https://www.digicert.com/services/v2/order/certificate/ssl_plus",
    headers={"X-DC-DEVKEY": "YOUR_API_KEY"},
    json={
        "certificate": {
            "common_name": "example.com",
            "dns_names": ["www.example.com"]
        },
        "organization": {"id": 123456},
        "validity_years": 1
    }
)
```

### 2. Infrastructure and Platform Solutions

#### Kubernetes with cert-manager

[cert-manager](https://cert-manager.io/) is a powerful Kubernetes native solution for certificate management.

**Implementation**:
```yaml
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.0/cert-manager.yaml

# Create ClusterIssuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx

# Create Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-tls
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - example.com
  - www.example.com
```

cert-manager monitors certificate expiration and automatically renews when needed.

#### AWS Certificate Manager (ACM)

ACM handles certificate provisioning, deployment, and renewal for AWS services.

**Implementation**:
```terraform
# Terraform example
resource "aws_acm_certificate" "cert" {
  domain_name       = "example.com"
  validation_method = "DNS"
  subject_alternative_names = ["www.example.com"]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Environment = "production"
  }
}

# Use with load balancer
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.front.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.front.arn
  }
}
```

ACM automatically renews certificates (typically 60 days before expiration).

#### HashiCorp Vault PKI Secrets Engine

Vault can function as a private CA or interface with external CAs for certificate management.

**Implementation**:
```hcl
# Enable PKI engine
vault secrets enable pki

# Configure CA and roles
vault write pki/root/generate/internal \
    common_name=example.com \
    ttl=8760h

vault write pki/roles/example-dot-com \
    allowed_domains=example.com \
    allow_subdomains=true \
    max_ttl=72h

# Create certificate rotation script
#!/bin/bash
CERT_TTL="48h"
DOMAIN="service.example.com"

# Generate new certificate
CERT_DATA=$(vault write -format=json pki/issue/example-dot-com \
    common_name=${DOMAIN} ttl=${CERT_TTL})

# Extract certificate, private key, and CA chain
echo ${CERT_DATA} | jq -r .data.certificate > /etc/ssl/cert.pem
echo ${CERT_DATA} | jq -r .data.private_key > /etc/ssl/key.pem
echo ${CERT_DATA} | jq -r .data.ca_chain > /etc/ssl/ca_chain.pem

# Reload service to apply new certificate
systemctl reload nginx
```

Schedule this script to run periodically before certificates expire.

### 3. Configuration Management and Automation

#### Ansible for Certificate Automation

Ansible playbooks can orchestrate certificate requests, deployment, and service reloads.

**Implementation**:
```yaml
# Ansible playbook for certificate rotation
---
- name: Rotate SSL Certificates
  hosts: webservers
  become: yes
  vars:
    domains:
      - example.com
      - www.example.com
    email: admin@example.com

  tasks:
    - name: Check certificate expiration
      command: "certbot certificates"
      register: cert_status
      changed_when: false

    - name: Request new certificates if needed
      command: "certbot certonly --nginx -d {{ domains | join(' -d ') }} --email {{ email }} --agree-tos --non-interactive"
      when: "'VALID:' not in cert_status.stdout or 'EXPIRY: 2023-' in cert_status.stdout"
      register: cert_renewed
      
    - name: Reload web server if certificates changed
      service:
        name: nginx
        state: reloaded
      when: cert_renewed.changed
```

#### CI/CD Pipeline Integration

Incorporate certificate rotation into existing CI/CD pipelines.

**Implementation (GitLab CI/CD)**:
```yaml
# GitLab CI/CD job for certificate rotation
certificate-rotation:
  stage: deploy
  script:
    - check_expiry=$(openssl x509 -enddate -noout -in /etc/ssl/cert.pem | cut -d= -f2)
    - expiry_date=$(date -d "$check_expiry" +%s)
    - current_date=$(date +%s)
    - days_until_expiry=$(( (expiry_date - current_date) / 86400 ))
    
    - if [ "$days_until_expiry" -lt "30" ]; then
    -   echo "Certificate expires in less than 30 days. Renewing..."
    -   certbot renew --deploy-hook "systemctl reload nginx"
    - else
    -   echo "Certificate still valid for $days_until_expiry days"
    - fi
  rules:
    - schedule: '0 0 * * 1'  # Run weekly on Mondays
```

## Best Practices for Automated Certificate Rotation

### 1. Monitoring and Alerting

- **Implement Certificate Monitoring**: Track certificate expiration dates
- **Set Up Alert Thresholds**: Configure alerts at 30, 14, and 7 days before expiration
- **Monitor Automation Status**: Alert on automation failures

**Implementation (Prometheus + Alertmanager)**:
```yaml
# Prometheus alert rule
groups:
- name: certificate_expiry
  rules:
  - alert: CertificateExpiryWarning
    expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 30
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "SSL Certificate expiring soon"
      description: "Certificate for {{ $labels.instance }} expires in less than 30 days"
```

### 2. Security Considerations

- **Use Short-lived Certificates**: 90 days or less is recommended
- **Implement Proper Key Management**: Secure private key storage
- **Follow Least Privilege Principle**: Limit automation account permissions
- **Implement Certificate Transparency Monitoring**: Monitor CT logs for unexpected certificates
- **Maintain Revocation Capability**: Ensure ability to revoke compromised certificates

### 3. Certificate Lifecycle Automation

- **Automate the Full Lifecycle**: Generation, validation, installation, renewal, and revocation
- **Implement Validation Testing**: Verify certificate validity after rotation
- **Use Immutable Infrastructure**: Deploy new instances rather than updating existing ones
- **Maintain Certificate Inventory**: Track all certificates, owners, and deployment locations

### 4. Operational Considerations

- **Stagger Renewals**: Avoid renewing all certificates simultaneously
- **Implement Progressive Rollout**: Test certificate deployment in staging before production
- **Plan for Failures**: Create fallback mechanisms for failed rotations
- **Document Procedures**: Maintain documentation for manual intervention if needed

## Implementation Examples for Common Environments

### Web Server (Nginx) with Let's Encrypt

```bash
# Install Certbot with Nginx plugin
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Obtain certificate and configure Nginx
sudo certbot --nginx -d example.com -d www.example.com

# Verify auto-renewal
echo "0 0,12 * * * root python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" | sudo tee -a /etc/crontab > /dev/null

# Test renewal process
sudo certbot renew --dry-run
```

### Containerized Applications

For Docker-based applications, use a sidecar container or shared volume approach:

```yaml
# Docker Compose example with renewal container
version: '3'

services:
  nginx:
    image: nginx:latest
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - certbot

  certbot:
    image: certbot/certbot
    volumes:
      - ./ssl:/etc/letsencrypt
      - ./certbot-renewal.sh:/usr/local/bin/certbot-renewal.sh
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
```

### Distributed Microservices Environment

For complex microservices architectures, consider a centralized certificate management service:

1. Deploy cert-manager in Kubernetes
2. Implement Istio or similar service mesh for TLS termination
3. Configure service mesh to pull certificates from a central secret store
4. Set up automated rotation with notifications to service owners

## Troubleshooting Certificate Rotation Issues

| Issue | Potential Causes | Resolution |
|-------|------------------|------------|
| Failed renewal | Network issues, validation failures | Check connectivity, DNS records, validation method |
| Certificate installed but not used | Incorrect path, missing reload | Verify paths, confirm service reload |
| Automation stopped working | Credentials expired, permissions changed | Check automation account, review logs |
| Invalid certificate chain | Missing intermediate certificates | Ensure complete chain installation |
| Service disruption during rotation | Improper handling of in-flight connections | Implement graceful rotation with connection draining |

## Conclusion

Automated certificate rotation is essential for maintaining secure, uninterrupted services. By implementing the appropriate automation strategy for your environment and following industry best practices, you can eliminate the risks associated with certificate expiration while enhancing your overall security posture.

Remember to:
- Choose the right automation tools for your environment
- Implement comprehensive monitoring and alerting
- Follow security best practices for certificate management
- Document processes for troubleshooting and emergency intervention

By treating certificate management as a critical operational process rather than a periodic manual task, you'll build more reliable and secure infrastructure.

---
title: Secure GCP Terraform Configurations
impact: HIGH
impactDescription: Cloud misconfigurations in GCP lead to data exposure, privilege escalation, and unauthorized access
tags: security, terraform, gcp, gke, iam, kubernetes, infrastructure, iac
attribution: Curated and enhanced for Prismor
---

## Secure GCP Terraform Configurations

Security best practices for Google Cloud Platform resources provisioned with Terraform.

### Google Cloud Storage (GCS)

**Incorrect:**
```hcl
resource "google_storage_bucket" "insecure" {
  name     = "example"; location = "EU"
  uniform_bucket_level_access = false
}
resource "google_storage_bucket_iam_member" "public" {
  role   = "roles/storage.admin"; member = "allUsers"  # Public!
}
```

**Correct:**
```hcl
resource "google_storage_bucket" "secure" {
  name     = "example"; location = "EU"
  uniform_bucket_level_access = true
  versioning { enabled = true }
  logging { log_bucket = "my-logging-bucket" }
}
resource "google_storage_bucket_iam_member" "restricted" {
  role   = "roles/storage.admin"; member = "user:jane@example.com"
}
```

### Google Compute Engine and Firewall

**Incorrect:**
```hcl
resource "google_compute_instance" "insecure" {
  can_ip_forward = true
  metadata = { serial-port-enable = true, enable-oslogin = false }
  network_interface { network = "default"; access_config {} }  # Public IP
}
resource "google_compute_firewall" "open" {
  allow { protocol = "tcp"; ports = [22, 3389] }
  source_ranges = ["0.0.0.0/0"]  # World-open SSH/RDP
}
```

**Correct:**
```hcl
resource "google_compute_instance" "secure" {
  can_ip_forward = false
  boot_disk { kms_key_self_link = google_kms_crypto_key.key.id }
  metadata = { enable-oslogin = true }
  network_interface { network = "default" }  # No public IP
  shielded_instance_config { enable_vtpm = true; enable_integrity_monitoring = true }
}
resource "google_compute_firewall" "restricted" {
  allow { protocol = "tcp"; ports = ["22"] }
  source_ranges = ["172.1.2.3/32"]; target_tags = ["ssh"]
}
```

### Google Kubernetes Engine (GKE)

**Incorrect:**
```hcl
resource "google_container_cluster" "insecure" {
  enable_legacy_abac = true; logging_service = "none"
  master_auth { username = "admin"; password = "password123" }
}
```

**Correct:**
```hcl
resource "google_container_cluster" "secure" {
  enable_legacy_abac = false; enable_shielded_nodes = true; enable_binary_authorization = true
  private_cluster_config { enable_private_nodes = true; master_ipv4_cidr_block = "10.0.0.0/28" }
  master_authorized_networks_config { cidr_blocks { cidr_block = "10.0.0.0/8" } }
  master_auth { client_certificate_config { issue_client_certificate = false } }
  network_policy { enabled = true }
}
resource "google_container_node_pool" "secure" {
  management { auto_repair = true; auto_upgrade = true }
}
```

### Cloud SQL

**Incorrect:**
```hcl
resource "google_sql_database_instance" "insecure" {
  settings {
    ip_configuration { ipv4_enabled = true; authorized_networks { value = "0.0.0.0/0" } }
  }
}
```

**Correct:**
```hcl
resource "google_sql_database_instance" "secure" {
  settings {
    ip_configuration { ipv4_enabled = false; require_ssl = true; private_network = google_compute_network.net.id }
  }
}
```

### IAM — Least Privilege

**Incorrect:**
```hcl
resource "google_project_iam_member" "dangerous" {
  role   = "roles/iam.serviceAccountTokenCreator"
  member = "serviceAccount:test-compute@developer.gserviceaccount.com"
}
```

**Correct:**
```hcl
resource "google_project_iam_member" "safe" {
  role = "roles/viewer"; member = "user:jane@example.com"
}
```

### KMS, Redis, BigQuery, Pub/Sub — Always Encrypt

**Incorrect:**
```hcl
resource "google_redis_instance" "insecure" { auth_enabled = false }
resource "google_bigquery_dataset" "unencrypted" { dataset_id = "example" }
resource "google_pubsub_topic" "unencrypted" { name = "topic" }
```

**Correct:**
```hcl
resource "google_redis_instance" "secure" {
  auth_enabled = true; transit_encryption_mode = "SERVER_AUTHENTICATION"
}
resource "google_bigquery_dataset" "encrypted" {
  default_encryption_configuration { kms_key_name = google_kms_crypto_key.example.name }
}
resource "google_pubsub_topic" "encrypted" { kms_key_name = google_kms_crypto_key.key.id }
```

### SSL Policies and DNS

**Incorrect:**
```hcl
resource "google_compute_ssl_policy" "weak" { min_tls_version = "TLS_1_0" }
resource "google_dns_managed_zone" "weak" {
  dnssec_config { default_key_specs { algorithm = "rsasha1" } }
}
```

**Correct:**
```hcl
resource "google_compute_ssl_policy" "strong" { min_tls_version = "TLS_1_2"; profile = "MODERN" }
resource "google_dns_managed_zone" "strong" {
  dnssec_config { default_key_specs { algorithm = "rsasha256"; key_length = 2048 } }
}
```

## Key Prevention Rules

1. **Disable public IPs** — no `access_config {}` on compute instances unless required
2. **Disable legacy ABAC on GKE** — `enable_legacy_abac = false` always
3. **Enable private clusters** — `enable_private_nodes = true` with authorized networks
4. **Encrypt all storage** — Cloud SQL, BigQuery, Pub/Sub, Redis all require KMS encryption
5. **Restrict firewall rules** — source_ranges must never be `0.0.0.0/0` for SSH/RDP
6. **Use TLS 1.2+** — `min_tls_version = "TLS_1_2"` on all SSL policies

**References:**
- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)
- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [Prismor](https://github.com/PrismorSec/prismor)

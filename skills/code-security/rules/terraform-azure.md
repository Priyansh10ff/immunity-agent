---
title: Secure Azure Terraform Configurations
impact: HIGH
impactDescription: Misconfigurations in Azure infrastructure lead to data breaches and unauthorized access
tags: security, terraform, azure, infrastructure, iac
attribution: Curated and enhanced for Prismor
---

## Secure Azure Terraform Configurations

Security best practices for Azure resources provisioned with Terraform.

### Storage Account Security

**Incorrect:**
```hcl
resource "azurerm_storage_account" "bad" {
  name                      = "storageaccountname"
  min_tls_version           = "TLS1_0"
  enable_https_traffic_only = false
}
resource "azurerm_storage_container" "bad" {
  container_access_type = "blob"  # Publicly readable
}
```

**Correct:**
```hcl
resource "azurerm_storage_account" "good" {
  name                      = "storageaccountname"
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
  network_rules { default_action = "Deny"; bypass = ["Metrics", "AzureServices"] }
}
resource "azurerm_storage_container" "good" {
  container_access_type = "private"
}
```

### App Service Security

**Incorrect:**
```hcl
resource "azurerm_app_service" "bad" {
  https_only               = false
  remote_debugging_enabled = true
  site_config { min_tls_version = "1.0"; cors { allowed_origins = ["*"] } }
  auth_settings { enabled = false }
}
```

**Correct:**
```hcl
resource "azurerm_app_service" "good" {
  https_only               = true
  remote_debugging_enabled = false
  site_config { min_tls_version = "1.2"; cors { allowed_origins = ["https://example.com"] } }
  auth_settings { enabled = true }
}
```

### Key Vault Security

**Incorrect:**
```hcl
resource "azurerm_key_vault" "bad" {
  purge_protection_enabled = false
  network_acls { bypass = "AzureServices"; default_action = "Allow" }
}
```

**Correct:**
```hcl
resource "azurerm_key_vault" "good" {
  soft_delete_retention_days = 7
  purge_protection_enabled   = true
  network_acls { bypass = "AzureServices"; default_action = "Deny" }
}
```

### Database Security

**Incorrect:**
```hcl
resource "azurerm_mssql_server" "bad" {
  minimum_tls_version           = "1.0"
  public_network_access_enabled = true
}
resource "azurerm_mysql_firewall_rule" "bad" {
  start_ip_address = "0.0.0.0"; end_ip_address = "255.255.255.255"
}
```

**Correct:**
```hcl
resource "azurerm_mssql_server" "good" {
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
}
resource "azurerm_mysql_firewall_rule" "good" {
  start_ip_address = "40.112.8.12"; end_ip_address = "40.112.8.17"
}
```

### AKS Security

**Incorrect:**
```hcl
resource "azurerm_kubernetes_cluster" "bad" {
  private_cluster_enabled         = false
  api_server_authorized_ip_ranges = []
}
```

**Correct:**
```hcl
resource "azurerm_kubernetes_cluster" "good" {
  private_cluster_enabled         = true
  disk_encryption_set_id          = azurerm_disk_encryption_set.example.id
  api_server_authorized_ip_ranges = ["192.168.0.0/16"]
}
```

### IAM — Avoid Wildcard Actions

**Incorrect:**
```hcl
resource "azurerm_role_definition" "bad" {
  permissions { actions = ["*"]; not_actions = [] }
}
```

**Correct:**
```hcl
resource "azurerm_role_definition" "good" {
  permissions {
    actions = [
      "Microsoft.Authorization/*/read",
      "Microsoft.Insights/alertRules/*"
    ]
    not_actions = []
  }
}
```

## Key Prevention Rules

1. **Enforce TLS 1.2 minimum** — `min_tls_version = "TLS1_2"` on all services
2. **Disable public network access** — set `public_network_access_enabled = false` wherever possible
3. **Enable purge protection** on Key Vaults
4. **Disable remote debugging** on App Services
5. **Use private clusters** for AKS with authorized IP ranges
6. **Use scoped IAM roles** — no wildcard `*` actions

**References:**
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [Prismor](https://github.com/PrismorSec/prismor)

# Azure SQL Security Auditor

## Overview

This Python3 script scans all Azure SQL databases across your subscriptions and audits key security configurations, including Transparent Data Encryption (TDE), auditing, Advanced Threat Protection (ATP), and geo-replication. 

## What It Checks and Why It Matters

| Configuration Item             | Description                                                    | Security Risk if Misconfigured                           |
|-------------------------------|----------------------------------------------------------------|----------------------------------------------------------|
| **Transparent Data Encryption (TDE)** | Ensures data at rest is encrypted automatically.               | Without TDE, sensitive data is stored unencrypted, increasing risk of data exposure if storage is compromised. |
| **Auditing (via Diagnostic Settings)** | Tracks database activities and writes audit logs to monitor access and changes. | Lack of auditing hinders detection of unauthorized or suspicious activities, limiting forensic capabilities. |
| **Auditing Retention Period** | Duration logs are retained for review and compliance.          | Short or no retention reduces ability to investigate historical incidents or meet compliance mandates. |
| **Advanced Threat Protection (ATP)** | Provides near real-time detection of anomalous activities and vulnerabilities. | Disabled ATP leaves the database vulnerable to undetected attacks or misconfigurations. |
| **Geo-Replication Configuration** | Enables replication of data to secondary regions for disaster recovery. | Missing geo-replication increases risk of data loss during regional outages or disasters. |

## Usage

1. Run the script with Python3 (requires the below Python3 libs).  
2. The script enumerates all subscriptions, SQL servers, and databases.  
3. See below for example output that can be expected. 

## Prerequisites

- Python3  
- pip install azure-identity azure-mgmt-resource azure-mgmt-sql  
- Azure account with sufficient permissions to read SQL and monitoring settings  

## Disclaimer

This tool provides a snapshot of specific security configurations. It does not guarantee comprehensive security. Regular reviews, patching, network controls, and Azure Security Center policies should complement this audit.

### 🔒 Azure SQL Security Audit Script

This script checks all Azure subscriptions and flags insecure or misconfigured SQL Server/database settings.

#### ✅ Example Output

```plaintext
📦 Subscription: My Company Prod Subscription (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
  🖥️ SQL Server: my-sql-server-prod (uksouth, RG: prod-resources)
    ⚠️ Insecure firewall rule: AllowAllIPs allows all IPs
    ❌ Server-level threat detection is disabled!
    ⚠️ No email addresses configured for threat alerts.
    ⚠️ Email to admins is not enabled.
    ⚠️ Threat detection retention period is 0 days.

    📂 Database: customerdb (Status: Online)
      ❌ TDE (encryption at rest) is not enabled!
      ❌ Auditing is not enabled!
      ⚠️ Threat detection is disabled at DB level!
      ⚠️ No email addresses configured for DB threat alerts.
      ⚠️ Email to admins not enabled at DB level.
      ⚠️ Threat detection retention period is 0 days.
      ⚠️ No geo-replication configured.

    📂 Database: ordersdb (Status: Online)
      🔁 Geo-replication: Linked to sql-server-dr in northeurope ```

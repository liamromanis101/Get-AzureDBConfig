# Azure SQL Security Auditor

## Overview

This PowerShell tool scans all Azure SQL databases across your subscriptions and audits key security configurations, including Transparent Data Encryption (TDE), auditing, Advanced Threat Protection (ATP), and geo-replication. It generates a consolidated CSV report highlighting potential security gaps to help you harden your Azure SQL environment.

## What It Checks and Why It Matters

| Configuration Item             | Description                                                    | Security Risk if Misconfigured                           |
|-------------------------------|----------------------------------------------------------------|----------------------------------------------------------|
| **Transparent Data Encryption (TDE)** | Ensures data at rest is encrypted automatically.               | Without TDE, sensitive data is stored unencrypted, increasing risk of data exposure if storage is compromised. |
| **Auditing (via Diagnostic Settings)** | Tracks database activities and writes audit logs to monitor access and changes. | Lack of auditing hinders detection of unauthorized or suspicious activities, limiting forensic capabilities. |
| **Auditing Retention Period** | Duration logs are retained for review and compliance.          | Short or no retention reduces ability to investigate historical incidents or meet compliance mandates. |
| **Advanced Threat Protection (ATP)** | Provides near real-time detection of anomalous activities and vulnerabilities. | Disabled ATP leaves the database vulnerable to undetected attacks or misconfigurations. |
| **Geo-Replication Configuration** | Enables replication of data to secondary regions for disaster recovery. | Missing geo-replication increases risk of data loss during regional outages or disasters. |

## Usage

1. Run the script with PowerShell (requires `Az` modules). It will prompt for Azure login and automatically install missing modules if needed.  
2. The script enumerates all subscriptions, SQL servers, and databases.  
3. Outputs a CSV report (`AzureSqlSecurityReport.csv`) with the audit findings.

## Prerequisites

- PowerShell 7+ (recommended) or Windows PowerShell  
- Azure PowerShell modules (`Az.Accounts`, `Az.Resources`, `Az.Sql`, `Az.Monitor`) — auto-installed by script if missing  
- Azure account with sufficient permissions to read SQL and monitoring settings  

## Disclaimer

This tool provides a snapshot of specific security configurations. It does not guarantee comprehensive security. Regular reviews, patching, network controls, and Azure Security Center policies should complement this audit.

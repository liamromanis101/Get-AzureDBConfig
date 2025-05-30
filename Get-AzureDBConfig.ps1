# Ensure Az module is installed and imported
if (-not (Get-Module -ListAvailable -Name Az)) {
    Install-Module -Name Az -Scope CurrentUser -Force
}
Import-Module Az

# Connect to Azure if not already connected
if (-not (Get-AzContext)) {
    Connect-AzAccount
}

# Initialize results
$results = @()

# Get all subscriptions
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id

    # Get all SQL servers in subscription
    $servers = Get-AzSqlServer

    foreach ($server in $servers) {
        $serverName = $server.ServerName
        $rgName = $server.ResourceGroupName

        # Get all SQL databases on the server
        $databases = Get-AzSqlDatabase -ResourceGroupName $rgName -ServerName $serverName | Where-Object { $_.DatabaseName -ne "master" }

        foreach ($db in $databases) {
            $dbName = $db.DatabaseName

            # Initialize flags
            $TDE_Enabled = $null
            $AuditingEnabled = $null
            $AuditingRetentionDays = $null
            $Threat_Detection_Enabled = $null
            $SendThreatDetectionAlerts = $null
            $Threat_DetectionRetentionDays = $null
            $GeoReplicationConfigured = $false

            # Transparent Data Encryption
            try {
                $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName
                $TDE_Enabled = $tde.Status -eq "Enabled"
            } catch {
                Write-Warning "TDE check failed for ${dbName}: $_"
            }

            # Auditing
            try {
                $auditing = Get-AzSqlDatabaseAudit -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName
                if ($auditing.AuditState -eq "Enabled") {
                    $AuditingEnabled = $true
                    $AuditingRetentionDays = $auditing.RetentionInDays
                } else {
                    $AuditingEnabled = $false
                }
            } catch {
                Write-Warning "Auditing check failed for ${dbName}: $_"
                $AuditingEnabled = $false
            }

            # Threat Detection
            try {
                $td = Get-AzSqlDatabaseAdvancedThreatProtectionSetting -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName
                $Threat_Detection_Enabled = $td.State -eq "Enabled"
            } catch {
                Write-Warning "Threat detection check failed for ${dbName}: $_"
                $Threat_Detection_Enabled = $false
            }

            # Diagnostic Settings (used to find alerts and retention)
            try {
                $resourceId = $db.Id
                if (-not [string]::IsNullOrEmpty($resourceId)) {
                    $diag = Get-AzDiagnosticSetting -ResourceId $resourceId
                    $SendThreatDetectionAlerts = ($diag.Metrics.Count -gt 0 -or $diag.Logs.Count -gt 0)
                } else {
                    Write-Warning "ResourceId is null for ${dbName}"
                    $SendThreatDetectionAlerts = $false
                }
            } catch {
                Write-Warning "Diagnostic settings check failed for ${dbName}: $_"
                $SendThreatDetectionAlerts = $false
            }

            # Geo-replication
            try {
                $replicationLinks = Get-AzSqlDatabaseReplicationLink -ResourceGroupName $rgName -ServerName $serverName -ErrorAction Stop
                $repLink = $replicationLinks | Where-Object { $_.DatabaseName -eq $dbName }

                if ($repLink) {
                    $replicationDetail = Get-AzSqlDatabaseReplicationLink `
                        -ResourceGroupName $rgName `
                        -ServerName $serverName `
                        -DatabaseName $dbName `
                        -PartnerResourceGroupName $repLink.PartnerResourceGroupName `
                        -PartnerServerName $repLink.PartnerServerName `
                        -ErrorAction Stop

                    if ($replicationDetail) {
                        $GeoReplicationConfigured = $true
                    }
                }
            } catch {
                Write-Warning "Geo-replication check failed for ${dbName}: $_"
                $GeoReplicationConfigured = $false
            }

            # Default unset/null values to 'false' or 'NotConfigured'
            if ($null -eq $TDE_Enabled) { $TDE_Enabled = $false }
            if ($null -eq $AuditingEnabled) { $AuditingEnabled = $false }
            if ($null -eq $Threat_Detection_Enabled) { $Threat_Detection_Enabled = $false }
            if ($null -eq $SendThreatDetectionAlerts) { $SendThreatDetectionAlerts = $false }
            if ($null -eq $GeoReplicationConfigured) { $GeoReplicationConfigured = $false }

            if (-not $AuditingRetentionDays) { $AuditingRetentionDays = "NotConfigured" }
            if (-not $Threat_DetectionRetentionDays) { $Threat_DetectionRetentionDays = "NotConfigured" }

            # Collect results
            $results += [PSCustomObject]@{
                SubscriptionName              = $sub.Name
                SubscriptionId                = $sub.Id
                ResourceGroupName             = $rgName
                ServerName                    = $serverName
                DatabaseName                  = $dbName
                TDE_Enabled                   = $TDE_Enabled
                AuditingEnabled               = $AuditingEnabled
                AuditingRetentionDays         = $AuditingRetentionDays
                Threat_Detection_Enabled      = $Threat_Detection_Enabled
                SendThreatDetectionAlerts     = $SendThreatDetectionAlerts
                Threat_DetectionRetentionDays = $Threat_DetectionRetentionDays
                GeoReplicationConfigured      = $GeoReplicationConfigured
            }
        }
    }
}

# Export results
$results | Export-Csv -Path "./SqlDatabaseSecurityReport.csv" -NoTypeInformation
Write-Host "✅ Report written to SqlDatabaseSecurityReport.csv"

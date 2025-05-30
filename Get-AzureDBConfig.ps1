# Ensure Az modules are installed and imported
$modules = @("Az.Accounts", "Az.Resources", "Az.Sql", "Az.Monitor")
foreach ($mod in $modules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Module $mod not found. Installing..."
        Install-Module -Name $mod -Scope CurrentUser -Force
    }
    Import-Module $mod -ErrorAction Stop
}

# Login to Azure
Write-Host "Logging into Azure..."
Connect-AzAccount -ErrorAction Stop

# Optional: Set Verbose preference
$VerbosePreference = "Continue"

# Prepare output array
$results = @()

# Get all subscriptions
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Write-Host "Processing subscription: $($sub.Name) ($($sub.Id))"
    Set-AzContext -Subscription $sub.Id -ErrorAction Stop

    # Get SQL Servers in subscription
    $servers = Get-AzSqlServer
    foreach ($server in $servers) {
        $serverName = $server.ServerName
        $rgName = $server.ResourceGroupName
        Write-Verbose "Processing SQL Server: $serverName in resource group $rgName"

        # Get SQL Databases on server
        $databases = Get-AzSqlDatabase -ResourceGroupName $rgName -ServerName $serverName
        foreach ($db in $databases) {
            $dbName = $db.DatabaseName
            Write-Verbose "Processing database: $dbName"

            # Initialize variables
            $TDE_Enabled = $null
            $Threat_Detection_Enabled = $null
            $AuditingEnabled = $false
            $AuditingRetentionDays = $null
            $Threat_DetectionRetentionDays = $null
            $SendThreatDetectionAlerts = $false
            $GeoReplicationConfigured = $false

            # Get TDE status
            try {
                Write-Verbose "Getting TDE status for database '$dbName'..."
                $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName -ErrorAction Stop
                $TDE_Enabled = if ($tde.Status -eq 'Enabled') { $true } else { $false }
            } catch {
                Write-Warning "Could not retrieve TDE status for database '$dbName' on server '$serverName'. Check permissions and module versions."
            }

            # Get Auditing via Diagnostic Settings
            try {
                Write-Verbose "Getting Diagnostic Settings for database '$dbName'..."
                $dbResourceId = $db.Id
                $diagSettings = Get-AzDiagnosticSetting -ResourceId $dbResourceId -ErrorAction Stop
                if ($diagSettings) {
                    $AuditingEnabled = $true
                    if ($diagSettings.RetentionPolicy) {
                        $AuditingRetentionDays = $diagSettings.RetentionPolicy.Days
                    }
                }
            } catch {
                Write-Warning "Could not retrieve auditing (diagnostic settings) for database '$dbName'."
            }

            # Get Advanced Threat Protection (ATP) status
            try {
                Write-Verbose "Getting Advanced Threat Protection status for database '$dbName'..."
                $threatDetection = Get-AzSqlDatabaseAdvancedThreatProtectionSetting -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName -ErrorAction Stop
                $Threat_Detection_Enabled = if ($threatDetection.State -eq 'Enabled') { $true } else { $false }
                if ($Threat_Detection_Enabled) {
                    $SendThreatDetectionAlerts = $threatDetection.EmailAdmins
                    $Threat_DetectionRetentionDays = $threatDetection.RetentionDays
                }
            } catch {
                Write-Warning "Could not retrieve Threat Detection status for database '$dbName'. Verify Az.Sql module version and permissions."
            }

            # Get Geo-Replication info by enumerating replication links WITHOUT PartnerResourceGroupName
            try {
                Write-Verbose "Checking geo-replication for database '$dbName'..."
                # This gets replication links without requiring PartnerResourceGroupName
                $replications = Get-AzSqlDatabaseReplicationLink -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName -ErrorAction Stop

                if ($replications -and $replications.Count -gt 0) {
                    # There are geo-replication links configured
                    $GeoReplicationConfigured = $true
                    # Optionally, you could collect info about partner servers here if desired
                } else {
                    $GeoReplicationConfigured = $false
                }
            } catch {
                Write-Warning "Could not retrieve geo-replication info for database '$dbName'."
            }

            # Add to results
            $results += [PSCustomObject]@{
                SubscriptionName              = $sub.Name
                SubscriptionId                = $sub.Id
                ResourceGroupName             = $rgName
                ServerName                   = $serverName
                DatabaseName                 = $dbName
                TDE_Enabled                  = $TDE_Enabled
                AuditingEnabled              = $AuditingEnabled
                AuditingRetentionDays        = $AuditingRetentionDays
                Threat_Detection_Enabled     = $Threat_Detection_Enabled
                SendThreatDetectionAlerts    = $SendThreatDetectionAlerts
                Threat_DetectionRetentionDays = $Threat_DetectionRetentionDays
                GeoReplicationConfigured     = $GeoReplicationConfigured
            }
        }
    }
}

# Export results to CSV
$outputFile = "AzureSqlSecurityReport.csv"
Write-Host "Exporting results to $outputFile"
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "Audit completed."

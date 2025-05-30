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
                $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName -ErrorAction Stop
                $TDE_Enabled = if ($tde.Status -eq 'Enabled') { $true } else { $false }
            } catch {
                Write-Warning "Could not retrieve TDE status for '$dbName'."
            }

            # Get auditing settings (diagnostic settings)
            try {
                $diagSettings = Get-AzDiagnosticSetting -ResourceId $db.Id -ErrorAction Stop
                if ($diagSettings) {
                    $AuditingEnabled = $true
                    if ($diagSettings.RetentionPolicy) {
                        $AuditingRetentionDays = $diagSettings.RetentionPolicy.Days
                    }
                }
            } catch {
                Write-Warning "Could not retrieve diagnostic settings for '$dbName'."
            }

            # Get advanced threat protection
            try {
                $threatDetection = Get-AzSqlDatabaseAdvancedThreatProtectionSetting -ResourceGroupName $rgName -ServerName $serverName -DatabaseName $dbName -ErrorAction Stop
                $Threat_Detection_Enabled = ($threatDetection.State -eq 'Enabled')
                if ($Threat_Detection_Enabled) {
                    $SendThreatDetectionAlerts = $threatDetection.EmailAdmins
                    $Threat_DetectionRetentionDays = $threatDetection.RetentionDays
                }
            } catch {
                Write-Warning "Could not retrieve threat detection settings for '$dbName'."
            }

            # Geo-replication detection
            try {
                $GeoReplicationConfigured = $false

                # Enumerate all replication links at the server level
                $serverLinks = Get-AzSqlDatabaseReplicationLink -ResourceGroupName $rgName -ServerName $serverName -ErrorAction Stop

                # Try to find a link that matches the current database
                $repLink = $serverLinks | Where-Object { $_.DatabaseName -eq $dbName }

                if ($repLink) {
                    $GeoReplicationConfigured = $true

                    # Optional: Confirm replication by calling again with required parameters
                    try {
                        $linkDetails = Get-AzSqlDatabaseReplicationLink `
                            -ResourceGroupName $rgName `
                            -ServerName $serverName `
                            -DatabaseName $dbName `
                            -PartnerResourceGroupName $repLink.PartnerResourceGroupName `
                            -PartnerServerName $repLink.PartnerServerName `
                            -ErrorAction Stop
                    } catch {
                        Write-Warning "Replication link exists for '$dbName', but could not retrieve full details."
                    }
                 }
             } catch {
                 Write-Warning "Could not enumerate replication links for server '$serverName': $_"
                 $GeoReplicationConfigured = $false
             }


            # Default unset/null values to 'false' or 'NotConfigured'
            if ($null -eq $TDE_Enabled) { $TDE_Enabled = $false }
            if ($null -eq $AuditingEnabled) { $AuditingEnabled = $false }
            if ($null -eq $Threat_Detection_Enabled) { $Threat_Detection_Enabled = $false }
            if ($null -eq $SendThreatDetectionAlerts) { $SendThreatDetectionAlerts = $false }
            if ($null -eq $GeoReplicationConfigured) { $GeoReplicationConfigured = $false }


            # Append result
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
$outputFile = "AzureSqlSecurityReport.csv"
Write-Host "Exporting results to $outputFile"
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "Security audit completed."

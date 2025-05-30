# Ensure required modules are installed
function Ensure-AzModule {
    param ([string]$ModuleName)
    $installed = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue
    if (-not $installed) {
        Write-Host "Installing module $ModuleName..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Force -Scope CurrentUser
    } else {
        Write-Host "Module $ModuleName is already installed." -ForegroundColor Green
    }
}

# Ensure modules are present
Ensure-AzModule -ModuleName "Az.Accounts"
Ensure-AzModule -ModuleName "Az.Resources"
Ensure-AzModule -ModuleName "Az.Sql"
Ensure-AzModule -ModuleName "Az.Monitor"

# Log in to Azure
Connect-AzAccount

# Prepare results array
$results = @()
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Write-Host "`nProcessing Subscription: $($sub.Name)" -ForegroundColor Cyan
    Set-AzContext -SubscriptionId $sub.Id

    $sqlServers = Get-AzSqlServer
    foreach ($server in $sqlServers) {
        $databases = Get-AzSqlDatabase -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName

        foreach ($db in $databases) {
            if ($db.DatabaseName -eq "master") { continue }
            Write-Host "  Checking Database: $($db.DatabaseName)" -ForegroundColor Yellow

            # Transparent Data Encryption
            $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -DatabaseName $db.DatabaseName

            # Geo-replication
            try {
                $partnerRG = $db.ReplicationLinks | Select-Object -First 1 | ForEach-Object { $_.PartnerResourceGroupName }

                if ($partnerRG) {
                    $replicationLinks = Get-AzSqlDatabaseReplicationLink `
                        -ResourceGroupName $server.ResourceGroupName `
                        -ServerName $server.ServerName `
                        -DatabaseName $db.DatabaseName `
                        -PartnerResourceGroupName $partnerRG

                    $isGeoReplicated = if ($replicationLinks) { $true } else { $false }
                } else {
                    $isGeoReplicated = $false
                }
            } catch {
                Write-Warning "    Could not retrieve replication info for $($db.DatabaseName): $($_.Exception.Message)"
                $isGeoReplicated = "Unknown"
            }

            # Build the resource ID for diagnostic settings
            $resourceId = "/subscriptions/$($sub.Id)/resourceGroups/$($server.ResourceGroupName)/providers/Microsoft.Sql/servers/$($server.ServerName)/databases/$($db.DatabaseName)"

            # Diagnostic Settings (Auditing)
            try {
                $diagSettings = Get-AzDiagnosticSetting -ResourceId $resourceId
                $auditSetting = $diagSettings | Where-Object {
                    $_.Enabled -eq $true -and $_.Logs.Category -contains "SQLSecurityAuditEvents"
                }
            } catch {
                Write-Warning "    Could not retrieve diagnostic settings for $($db.DatabaseName): $($_.Exception.Message)"
                $auditSetting = $null
            }

            # Advanced Threat Protection
            try {
                $td = Get-AzSqlDatabaseAdvancedThreatProtectionSetting `
                    -ResourceGroupName $server.ResourceGroupName `
                    -ServerName $server.ServerName `
                    -DatabaseName $db.DatabaseName
            } catch {
                Write-Warning "    Could not retrieve ATP settings for $($db.DatabaseName): $($_.Exception.Message)"
                $td = $null
            }

            # Compose result
            $results += [PSCustomObject]@{
                Subscription                     = $sub.Name
                ResourceGroup                    = $server.ResourceGroupName
                ServerName                       = $server.ServerName
                DatabaseName                     = $db.DatabaseName
                TDE_Enabled                      = $tde.Status
                Auditing_Enabled                 = if ($auditSetting) { "Enabled" } else { "Disabled" }
                Auditing_Retention_Days          = if ($auditSetting) { $auditSetting.RetentionPolicy.Days } else { "N/A" }
                Threat_Detection_Enabled         = if ($td) { $td.State } else { "Unknown" }
                GeoReplication_Configured        = $isGeoReplicated
            }
        }
    }
}

# Export to CSV
$csvPath = "AzureSqlSecurityReport.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "`n✅ Security audit completed. Results saved to $csvPath" -ForegroundColor Green

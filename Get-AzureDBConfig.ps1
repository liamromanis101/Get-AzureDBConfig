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
Ensure-AzModule -ModuleName "Az.Security"

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
            $replicationLinks = Get-AzSqlDatabaseReplicationLink -ServerName $server.ServerName `
                -DatabaseName $db.DatabaseName -ResourceGroupName $server.ResourceGroupName
            $isGeoReplicated = if ($replicationLinks) { $true } else { $false }

            # Diagnostic Settings (Auditing via Azure Monitor)
            $diagSettings = Get-AzDiagnosticSetting -ResourceId $db.Id
            $auditSetting = $diagSettings | Where-Object {
                $_.Enabled -eq $true -and $_.Logs.Category -contains "SQLSecurityAuditEvents"
            }

            # Defender for SQL (Threat Detection)
            $td = Get-AzSecurityAlertPolicy -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -DatabaseName $db.DatabaseName

            # Compose result
            $results += [PSCustomObject]@{
                Subscription                     = $sub.Name
                ResourceGroup                    = $server.ResourceGroupName
                ServerName                       = $server.ServerName
                DatabaseName                     = $db.DatabaseName
                TDE_Enabled                      = $tde.Status
                Auditing_Enabled                 = if ($auditSetting) { "Enabled" } else { "Disabled" }
                Auditing_Retention_Days          = $auditSetting.RetentionPolicy.Days
                Threat_Detection_Enabled         = $td.State
                Threat_Detection_Emails          = ($td.EmailAddresses -join ", ")
                Threat_Detection_Retention_Days  = $td.RetentionDays
                GeoReplication_Configured        = $isGeoReplicated
            }
        }
    }
}

# Export to CSV
$csvPath = "AzureSqlSecurityReport.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "`n✅ Security audit completed. Results saved to $csvPath" -ForegroundColor Green

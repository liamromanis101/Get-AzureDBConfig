# Function to ensure required Az modules are installed
function Ensure-AzModule {
    param (
        [string]$ModuleName
    )
    $installed = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue
    if (-not $installed) {
        Write-Host "Installing module $ModuleName..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Force -Scope CurrentUser
    } else {
        Write-Host "Module $ModuleName is already installed." -ForegroundColor Green
    }
}

# Ensure required modules
Ensure-AzModule -ModuleName "Az.Accounts"
Ensure-AzModule -ModuleName "Az.Resources"
Ensure-AzModule -ModuleName "Az.Sql"

# Connect to Azure
Connect-AzAccount

# Initialize results array
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

            # Auditing
            $audit = Get-AzSqlDatabaseAuditing -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -DatabaseName $db.DatabaseName

            # Threat Detection / Advanced Data Security
            $td = Get-AzSqlDatabaseThreatDetectionPolicy -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -DatabaseName $db.DatabaseName

            # Geo-replication check
            $replicationLinks = Get-AzSqlDatabaseReplicationLink -ServerName $server.ServerName `
                -DatabaseName $db.DatabaseName -ResourceGroupName $server.ResourceGroupName
            $isGeoReplicated = if ($replicationLinks) { $true } else { $false }

            # Build the result object
            $results += [PSCustomObject]@{
                Subscription                     = $sub.Name
                ResourceGroup                    = $server.ResourceGroupName
                ServerName                       = $server.ServerName
                DatabaseName                     = $db.DatabaseName
                TDE_Enabled                      = $tde.Status
                Auditing_Enabled                 = $audit.State
                Auditing_Retention_Days          = $audit.RetentionInDays
                Threat_Detection_Enabled         = $td.State
                Threat_Detection_Emails          = ($td.EmailAddresses -join ", ")
                Threat_Detection_Retention_Days  = $td.RetentionDays
                GeoReplication_Configured        = $isGeoReplicated
            }
        }
    }
}

# Export to CSV
$csvPath = "AzureSqlSecurityDetails.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "`n✅ Security audit completed. Results saved to $csvPath" -ForegroundColor Green

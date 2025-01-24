<#
    Author:			Arne Tiedemann Skaylink GmbH
    E-Mail:			Arne.Tiedemann@skaylink.com
    Date:			2023-03-06
    Description:	This Script install the Azure arc Agent
#>

param(
    [switch]
    $disconnect
)

# Set TLS to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

###########################################################################
# Variables
###########################################################################
$azureCloud = 'AzureCloud'
$connectToCloud = $false
$env:AUTH_TYPE = 'principal'
<#
    Enable Azure Connected Machine Agent alloed for these extension for Tier 0 System
    - Microsoft.Azure.Monitor                   = AzureMonitorWindowsAgent
    - Microsoft.Azure.AzureDefenderForServers   = MDE.Windows
    - Microsoft.CPlat.Core                      = WindowsPatchExtension
    - Microsoft.SoftwareUpdateManagement        = WindowsOsUpdateExtension
#>
$extensionsAllowList = 'Microsoft.Azure.Monitor/AzureMonitorWindowsAgent,Microsoft.Azure.AzureDefenderForServers/MDE.Windows,Microsoft.CPlat.Core/WindowsPatchExtension,Microsoft.SoftwareUpdateManagement/WindowsOsUpdateExtension'

$pathPrg = 'C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe'
$updateExtension = $false
###########################################################################
# Functions
###########################################################################
function GetRegistryValue {
    Param(
        [Parameter(Mandatory)]
        [STRING]$Path,
        [Parameter(Mandatory)]
        [STRING]$Name

    )

    $Path = ('Registry::{0}' -f $Path)

    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
        Return (Get-ItemProperty -Path $Path -Name $Name).$Name
    } else {
        Return $null
    }
}
###########################################################################
# Script
###########################################################################
# Get Client configuration
$Config = @{
    arcSpnId          = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcSpnId')
    arcSecret         = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcSecret')
    arcSubscriptionId = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcSubscriptionId')
    arcTenantId       = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcTenantId')
    arcLocation       = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcLocation')
    arcResourceGroup  = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcResourceGroup')
    arcGateway        = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcGatewayId')
    arcProxyUrl       = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcProxyUrl')
    arcTier0          = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureArc' -Name 'arcTier0')
}

# Add the service principal application ID and secret here
$servicePrincipalSecret = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Config.arcSecret))

#Install if Azure Connected machine agent is not installed
if ((Test-Path -Path $pathPrg -ErrorAction SilentlyContinue) -ne $true -and $Config.arcSecret.length -gt 64) {
    try {
        # Download the installation package
        if ($config.arcProxyUrl.length -gt 0) {
            #Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/azcmagent-windows' -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1" -Proxy $config.arcProxyUrl
            Invoke-WebRequest -UseBasicParsing -Uri 'https://gbl.his.arc.azure.com/azcmagent-windows' -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1" -Proxy $config.arcProxyUrl
            # Install the hybrid agent
            & "$env:TEMP\install_windows_azcmagent.ps1" -Proxy $config.arcProxyUrl
            if ($LASTEXITCODE -ne 0) {
                exit 1
            }

        } else {
            #Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/azcmagent-windows' -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1"
            Invoke-WebRequest -UseBasicParsing -Uri 'https://gbl.his.arc.azure.com/azcmagent-windows' -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1"
            # Install the hybrid agent
            & "$env:TEMP\install_windows_azcmagent.ps1"
            if ($LASTEXITCODE -ne 0) {
                exit 1
            }
        }

        # Run connect command
        $connectToCloud = $true
    } catch {
        Write-Host $_.Exception.Message
        exit
    }
}

# If installed fIrst check running configuration
$arcConfig = & $pathPrg show -j | ConvertFrom-Json
$arcLocalSettings = & $pathPrg config list -j | ConvertFrom-Json

# check config and if somthing is different reconnect to the correct settings
if (
        ($arcConfig.resourceGroup -ne $config.arcResourceGroup -or
    $arcConfig.subscriptionId -ne $config.arcSubscriptionId -or
    $arcConfig.tenantId -ne $config.arcTenantId) -and ($null -ne $arcConfig.resourceGroup -or
        $null -ne $arcConfig.subscriptionId -or
        $null -ne $arcConfig.tenantId)
) {
    Write-Host "`n`n`tAzure Connected Machine Agent configuration is not as desired, we disconnect and reconnect the device`n`n" -ForegroundColor Red
    # First disconnect this agent
    & $pathPrg disconnect --service-principal-id $Config.arcSpnId --service-principal-secret $servicePrincipalSecret --user-tenant-id $Config.arcTenantId

    if ($? -eq $true) {
        $connectToCloud = $true
    }
}

# If state is disconnected connect it with same configuration
# this will help if machine is in expired state
if ($arcConfig.status -eq 'Disconnected') {
    $connectToCloud = $true
}

# Checking running configuration
if ($arcConfig.upstreamProxy.length -eq 0 -and $config.arcProxyUrl.length -gt 0) {
    Write-Host ('Configure system to use a proxy server url: {0}' -f $config.arcProxyUrl) -ForegroundColor Green
    & $pathPrg config set proxy.url $config.arcProxyUrl
} elseif ($arcConfig.upstreamProxy.length -gt 0 -and $config.arcProxyUrl.length -eq 0) {
    Write-Host 'Configure system to connect directly' -ForegroundColor Green
    & $pathPrg config clear proxy.url
}

# Start connect or reconnect to Azure
if ($connectToCloud -eq $true -and $Config.arcSpnId.Length -gt 0 -and $servicePrincipalSecret.Length -gt 0) {
    if ($config.arcGateway.length -eq 0) {
        Write-Host 'Direct connect to Arc' -ForegroundColor Green
        & $pathPrg connect --service-principal-id $Config.arcSpnId --service-principal-secret $servicePrincipalSecret --resource-group $Config.arcResourceGroup --tenant-id $Config.arcTenantId --location $Config.arcLocation --subscription-id $Config.arcSubscriptionId --cloud $azureCloud --correlation-id ([guid]::NewGuid()).guid
    } else {
        Write-Host 'Gateway connect to Arc' -ForegroundColor Green
        & $pathPrg connect --service-principal-id $Config.arcSpnId --service-principal-secret $servicePrincipalSecret --resource-group $Config.arcResourceGroup --tenant-id $Config.arcTenantId --location $Config.arcLocation --subscription-id $Config.arcSubscriptionId --cloud $azureCloud --correlation-id ([guid]::NewGuid()).guid --gateway-id $config.arcGateway
    }
}

<#
Possible valid values from Version 1.48.02881.1941

incomingconnections.enabled (preview)
incomingconnections.ports (preview)
connection.type (preview)
proxy.url
proxy.bypass
extensions.allowlist
extensions.blocklist
guestconfiguration.enabled
extensions.enabled
config.mode
guestconfiguration.agent.cpulimit
extensions.agent.cpulimit
#>

# Secure Tier0 systems
if ($config.arcTier0 -eq $true -and
    (($arcLocalSettings.localsettings | Where-Object Key -EQ 'incomingconnections.enabled').value -ne $false) -or
    (($arcLocalSettings.localsettings | Where-Object Key -EQ 'guestconfiguration.enabled').value -ne $false)
) {
    Write-Host 'Configure system for Tier 0 environment and disable some function' -ForegroundColor Green
    & $pathPrg config set incomingconnections.enabled false
    & $pathPrg config set guestconfiguration.enabled false
}

if ($config.arcTier0 -eq $true) {
    foreach ($extension in $extensionsAllowList.Split(',')) {
        if (($arcLocalSettings.localsettings | Where-Object Key -EQ 'extensions.allowlist').value -notcontains $extension) {
            $updateExtension = $true
        }
    }

    # Update if needed
    if ($updateExtension -eq $true) {
        Write-Host 'Configure system for Tier 0 environment and set extensionallowlist' -ForegroundColor Green
        & $pathPrg config set extensions.allowlist $extensionsAllowList
    }
}

# If we showld disconnect do it
if ($disconnect -eq $true) {
    & $pathPrg disconnect --service-principal-id $Config.arcSpnId --service-principal-secret $servicePrincipalSecret
}

###########################################################################
# Finally
###########################################################################
# Cleaning Up the workspace
###########################################################################
# End
###########################################################################


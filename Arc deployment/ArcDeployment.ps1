<#
    Author:			Arne Tiedemann Skaylink GmbH
    E-Mail:			Arne.Tiedemann@skaylink.com
    Date:			2023-03-06
    Description:	This Script install the Azure arc Agent
#>

# Set TLS to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

###########################################################################
# Variables
###########################################################################
$azureCloud = 'AzureCloud'
$connectToCloud = $false
$env:AUTH_TYPE = 'principal'

$pathPrg = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
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
}

# Add the service principal application ID and secret here
$servicePrincipalSecret = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Config.arcSecret))

#Install if Azure Connected machine agent is not installed
if ((Test-Path -Path $pathPrg -ErrorAction SilentlyContinue) -ne $true -and $Config.arcSecret.length -gt 64) {
    try {
        # Download the installation package
        Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/azcmagent-windows' -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1"

        # Install the hybrid agent
        & "$env:TEMP\install_windows_azcmagent.ps1"
        if ($LASTEXITCODE -ne 0) {
            exit 1
        }

        # Run connect command
        $connectToCloud = $true
    } catch {
        Write-Host $_.Exception.Message
    }
} else {
    # If installed fIrst check running configuration
    $arcConfig = & $pathPrg show -j | ConvertFrom-Json

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
    if ($arcConfig.status -eq 'Disconnected'){
        $connectToCloud = $true
    }
}


# Start connect or reconnect to Azure
if ($connectToCloud -eq $true -and $Config.arcSpnId.Length -gt 0 -and $servicePrincipalSecret.Length -gt 0) {
    & $pathPrg connect --service-principal-id $Config.arcSpnId --service-principal-secret $servicePrincipalSecret --resource-group $Config.arcResourceGroup --tenant-id $Config.arcTenantId --location $Config.arcLocation --subscription-id $Config.arcSubscriptionId --cloud $azureCloud  --correlation-id ([guid]::NewGuid()).guid
}
###########################################################################
# Finally
###########################################################################
# Cleaning Up the workspace
###########################################################################
# End
###########################################################################


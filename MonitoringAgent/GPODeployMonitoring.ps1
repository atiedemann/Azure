
<#
Author:			Arne Tiedemann
E-Mail:			Arne.Tiedemann@tiedemanns.info
Date:			2020-10-21
Description:	This Script install the Azure monitoring agent
#>

###########################################################################
# Variables
###########################################################################
$source = @" 
using System; 
using System.Collections.Generic; 
using System.Text; 
using System.Runtime.InteropServices; 
using System.ComponentModel; 
using System.Net.NetworkInformation; 
 
namespace Microsoft.WindowsAzure.Internal 
{ 
    /// <summary> 
    /// A simple DHCP client. 
    /// </summary> 
    public class DhcpClient : IDisposable 
    { 
        public DhcpClient() 
        { 
            uint version; 
            int err = NativeMethods.DhcpCApiInitialize(out version); 
            if (err != 0) 
                throw new Win32Exception(err); 
        } 
 
        public void Dispose() 
        { 
            NativeMethods.DhcpCApiCleanup(); 
        } 
 
        /// <summary> 
        /// Gets the available interfaces that are enabled for DHCP. 
        /// </summary> 
        /// <remarks> 
        /// The operational status of the interface is not assessed. 
        /// </remarks> 
        /// <returns></returns> 
        public static IEnumerable<NetworkInterface> GetDhcpInterfaces() 
        { 
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces()) 
            { 
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet) continue; 
                if (!nic.Supports(NetworkInterfaceComponent.IPv4)) continue; 
                IPInterfaceProperties props = nic.GetIPProperties(); 
                if (props == null) continue; 
                IPv4InterfaceProperties v4props = props.GetIPv4Properties(); 
                if (v4props == null) continue; 
                if (!v4props.IsDhcpEnabled) continue; 
 
                yield return nic; 
            } 
        } 
 
        /// <summary> 
        /// Requests DHCP parameter data. 
        /// </summary> 
        /// <remarks> 
        /// Windows serves the data from a cache when possible.   
        /// With persistent requests, the option is obtained during boot-time DHCP negotiation. 
        /// </remarks> 
        /// <param name="optionId">the option to obtain.</param> 
        /// <param name="isVendorSpecific">indicates whether the option is vendor-specific.</param> 
        /// <param name="persistent">indicates whether the request should be persistent.</param> 
        /// <returns></returns> 
        public byte[] DhcpRequestParams(string adapterName, uint optionId) 
        { 
            uint bufferSize = 1024; 
        Retry: 
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize); 
            try 
            { 
                NativeMethods.DHCPCAPI_PARAMS_ARRAY sendParams = new NativeMethods.DHCPCAPI_PARAMS_ARRAY(); 
                sendParams.nParams = 0; 
                sendParams.Params = IntPtr.Zero; 
 
                NativeMethods.DHCPCAPI_PARAMS recv = new NativeMethods.DHCPCAPI_PARAMS(); 
                recv.Flags = 0x0; 
                recv.OptionId = optionId; 
                recv.IsVendor = false; 
                recv.Data = IntPtr.Zero; 
                recv.nBytesData = 0; 
 
                IntPtr recdParamsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(recv)); 
                try 
                { 
                    Marshal.StructureToPtr(recv, recdParamsPtr, false); 
 
                    NativeMethods.DHCPCAPI_PARAMS_ARRAY recdParams = new NativeMethods.DHCPCAPI_PARAMS_ARRAY(); 
                    recdParams.nParams = 1; 
                    recdParams.Params = recdParamsPtr; 
 
                    NativeMethods.DhcpRequestFlags flags = NativeMethods.DhcpRequestFlags.DHCPCAPI_REQUEST_SYNCHRONOUS; 
 
                    int err = NativeMethods.DhcpRequestParams( 
                        flags, 
                        IntPtr.Zero, 
                        adapterName, 
                        IntPtr.Zero, 
                        sendParams, 
                        recdParams, 
                        buffer, 
                        ref bufferSize, 
                        null); 
 
                    if (err == NativeMethods.ERROR_MORE_DATA) 
                    { 
                        bufferSize *= 2; 
                        goto Retry; 
                    } 
 
                    if (err != 0) 
                        throw new Win32Exception(err); 
 
                    recv = (NativeMethods.DHCPCAPI_PARAMS)  
                        Marshal.PtrToStructure(recdParamsPtr, typeof(NativeMethods.DHCPCAPI_PARAMS)); 
 
                    if (recv.Data == IntPtr.Zero) 
                        return null; 
 
                    byte[] data = new byte[recv.nBytesData]; 
                    Marshal.Copy(recv.Data, data, 0, (int)recv.nBytesData); 
                    return data; 
                } 
                finally 
                { 
                    Marshal.FreeHGlobal(recdParamsPtr); 
                } 
            } 
            finally 
            { 
                Marshal.FreeHGlobal(buffer); 
            } 
        } 
 
        ///// <summary> 
        ///// Unregisters a persistent request. 
        ///// </summary> 
        //public void DhcpUndoRequestParams() 
        //{ 
        //    int err = NativeMethods.DhcpUndoRequestParams(0, IntPtr.Zero, null, this.ApplicationID); 
        //    if (err != 0) 
        //        throw new Win32Exception(err); 
        //} 
 
        #region Native Methods 
    } 
 
    internal static partial class NativeMethods 
    { 
        public const uint ERROR_MORE_DATA = 124; 
 
        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpRequestParams", CharSet = CharSet.Unicode, SetLastError = false)] 
        public static extern int DhcpRequestParams( 
            DhcpRequestFlags Flags, 
            IntPtr Reserved, 
            string AdapterName, 
            IntPtr ClassId, 
            DHCPCAPI_PARAMS_ARRAY SendParams, 
            DHCPCAPI_PARAMS_ARRAY RecdParams, 
            IntPtr Buffer, 
            ref UInt32 pSize, 
            string RequestIdStr 
            ); 
 
        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpUndoRequestParams", CharSet = CharSet.Unicode, SetLastError = false)] 
        public static extern int DhcpUndoRequestParams( 
            uint Flags, 
            IntPtr Reserved, 
            string AdapterName, 
            string RequestIdStr); 
 
        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpCApiInitialize", CharSet = CharSet.Unicode, SetLastError = false)] 
        public static extern int DhcpCApiInitialize(out uint Version); 
 
        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpCApiCleanup", CharSet = CharSet.Unicode, SetLastError = false)] 
        public static extern int DhcpCApiCleanup(); 
 
        [Flags] 
        public enum DhcpRequestFlags : uint 
        { 
            DHCPCAPI_REQUEST_PERSISTENT = 0x01, 
            DHCPCAPI_REQUEST_SYNCHRONOUS = 0x02, 
            DHCPCAPI_REQUEST_ASYNCHRONOUS = 0x04, 
            DHCPCAPI_REQUEST_CANCEL = 0x08, 
            DHCPCAPI_REQUEST_MASK = 0x0F 
        } 
 
        [StructLayout(LayoutKind.Sequential)] 
        public struct DHCPCAPI_PARAMS_ARRAY 
        { 
            public UInt32 nParams; 
            public IntPtr Params; 
        } 
 
        [StructLayout(LayoutKind.Sequential)] 
        public struct DHCPCAPI_PARAMS 
        { 
            public UInt32 Flags; 
            public UInt32 OptionId; 
            [MarshalAs(UnmanagedType.Bool)]  
            public bool IsVendor; 
            public IntPtr Data; 
            public UInt32 nBytesData; 
        } 
        #endregion 
    } 
} 
"@ 
Add-Type -TypeDefinition $source  
$DomainName = (Get-ADDomain).DnsRoot
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
###########################################################################
# Functions
###########################################################################
Function Confirm-AzureVM { 
     
    $detected = $False 
 
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Serviceprocess') 
 
    $vmbus = [System.ServiceProcess.ServiceController]::GetDevices() | where { $_.Name -eq 'vmbus' } 
 
    If ($vmbus.Status -eq 'Running') { 
        $client = New-Object Microsoft.WindowsAzure.Internal.DhcpClient 
        try { 
            [Microsoft.WindowsAzure.Internal.DhcpClient]::GetDhcpInterfaces() | % {  
                $val = $client.DhcpRequestParams($_.Id, 245) 
                if ($val -And $val.Length -eq 4) { 
                    $detected = $True 
                } 
            } 
        }
        finally { 
            $client.Dispose() 
        }     
    } 
    Write-Output $detected 
} 

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
    }
    else { Return $null }
}
###########################################################################
# Script
###########################################################################
# Check if it is an Azure Machine
$IsAzureMachine = Confirm-AzureVM
if ($IsAzureMachine -eq $true) {
    Write-Warning 'This maschine is an Azure VM! The Agent will not be installed on Azure virtual machines!'
    BREAK
}

# Get Client configuration
$Config = @{
    TenantId                = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\' -Name 'TenantId')
    ProxyServerUri          = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\' -Name 'ProxyServerUri')
    PathDownload            = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\' -Name 'PathDownload')
    NetworkPath             = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\' -Name 'NetworkPath')
    WorkspaceId             = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\LogAnalytics' -Name 'WorkspaceId')
    WorkspaceIdsToRemove    = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\LogAnalytics' -Name 'WorkspaceIdsToRemove')
    WorkspaceKey            = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\LogAnalytics' -Name 'WorkspaceKey')
    UseWSUS                 = (GetRegistryValue -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\SkayLink\Azure\LogAnalytics' -Name 'UseWSUS')
}

# Output Values
$Config

# Check if MMAgents should be installed
$Agent = ("{0}\MMASetup-AMD64" -f $Config.NetworkPath)
$AgentDep = ("{0}\InstallDependencyAgent-Windows.exe" -f $Config.NetworkPath)

if ((Test-Path -Path $Agent -ErrorAction SilentlyContinue) -eq $true )
{
    $AgentVersion = (Get-Item -Path ('{0}\setup.exe' -f $Agent) -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
    $AgentVersionLocal = (Get-Item -Path ('{0}\Microsoft Monitoring Agent\Agent\AgentControlPanel.exe' -f $env:ProgramFiles) -ErrorAction SilentlyContinue ).VersionInfo.ProductVersion

    if ($AgentVersionLocal -ne $AgentVersion) {
        $AgentInstall = $true
    }

    Write-Host (@"
Agent Version: {0}
Agent Network Version: {1}
Agent Installation: {2}
"@ -f $AgentVersionLocal, $AgentVersion, $AgentInstall)
}

# Check if the dependency Agent should be installed
if ((Test-Path -Path $AgentDep -ErrorAction SilentlyContinue) -eq $true)
{
    $AgentDepVersion = (Get-Item -Path $AgentDep -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
    $AgentDepVersionLocal = (Get-Item -Path ('{0}\Microsoft Dependency Agent\bin\MicrosoftDependencyAgent.exe' -f $env:ProgramFiles) -ErrorAction SilentlyContinue ).VersionInfo.ProductVersion

    if ($AgentDepVersionLocal -ne $AgentDepVersion) {
        $AgentDepInstall = $true
    }

    Write-Host (@"
Dependency Agent Version: {0}
Dependency Agent Network Version: {1}
Dependency Agent Installation: {2}
"@ -f $AgentDepVersionLocal, $AgentDepVersion, $AgentDepInstall)
}

# Run installation
if (
    (-not([STRING]::IsNullOrEmpty($Config.TenantId))) -and 
    (-not([STRING]::IsNullOrEmpty($Config.PathDownload))) -and 
    (-not([STRING]::IsNullOrEmpty($Config.NetworkPath))) -and 
    (-not([STRING]::IsNullOrEmpty($Config.WorkspaceId))) -and 
    (-not([STRING]::IsNullOrEmpty($Config.WorkspaceKey))))
{

    # Set preference
    $ProgressPreference = "SilentlyContinue"; 

    # Convert WS_ID and WS_KEY
    if ((-not([string]::IsNullOrWhiteSpace($Config.WorkspaceId))) -or (-not([string]::IsNullOrWhiteSpace($Config.WorkspaceKey)))) {
        $OPSINSIGHTS_WS_ID = $Config.WorkspaceId
        $OPSINSIGHTS_WS_KEY = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Config.WorkspaceKey))
    }

    # If one or both agents should be installed, do it :-)
    if ( $AgentInstall -eq $true -or $AgentDepInstall -eq $true )
    {
        if ((-not ([STRING]::IsNullOrWhiteSpace($OPSINSIGHTS_WS_ID))) -and (-not ([STRING]::IsNullOrWhiteSpace($OPSINSIGHTS_WS_KEY)))) {
            
            # Install / Update the MMAgent
            if ($AgentInstall -eq $true -and ($null -eq $AgentVersionLocal -or $Config.UseWSUS -eq 0)) {
                Copy-Item -Path $Agent -Destination ('{0}\' -f $Config.PathDownload) -Recurse -Force
                Write-Host 'Start installation Microsoft Management Agent' -ForegroundColor Yellow
                Start-Process `
                    -FilePath ('{0}\MMASetup-AMD64\Setup.exe' -f $Config.PathDownload) `
                    -ArgumentList ('/qn /l*v {0}\MonitoringAgent.log AcceptEndUserLicenseAgreement=1' -f $Config.PathDownload) `
                    -Wait
            }

            # Install / Update the Dependency Agent
            if ($AgentDepInstall -eq $true -and ($null -eq $AgentDepVersionLocal -or $Config.UseWSUS -eq 0)) {
                Copy-Item -Path $AgentDep -Destination ('{0}\' -f $Config.PathDownload) -Recurse -Force
                Write-Host 'Start installation Microsoft Dependency Agent' -ForegroundColor Yellow
                Start-Process -FilePath ('{0}\InstallDependencyAgent-Windows.exe' -f $Config.PathDownload) `
                    -ArgumentList "/S" `
                    -Wait
            }
        }
    }


    if (((-not([string]::IsNullOrWhiteSpace($OPSINSIGHTS_WS_ID))) -or (-not([string]::IsNullOrWhiteSpace($OPSINSIGHTS_WS_KEY))))) 
    {
        # Check Workspace ID and move to new one if ID is different
        # Set Variable
        Write-Host 'Check Workspace ID'
        $WSexists = $false
        # Try to geht agent running
        try {
            $MMAgent = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'

            # Remove previus unwanted workspaces
            foreach($i in $Config.WorkspaceIdsToRemove.Split(','))
            {
                if ($WS.workspaceId -eq $i) {
                    Write-Host 'Remove Workspace ID: ' -NoNewline
                    Write-Host $i -ForegroundColor Green

                    $MMAgent.RemoveCloudWorkspace($i)
                }
            }
            
            # Check if Workspace ID exists
            foreach ($WS in $MMAgent.GetCloudWorkspaces()) {
                # Remove only other workspaces if exists
                if ($WS.workspaceId -eq $OPSINSIGHTS_WS_ID)
                {
                    $WSexists = $true
                }
            }

            # Add Workspace if not exists
            if ($WSexists -eq $false) {
                $MMAgent.AddCloudWorkspace($OPSINSIGHTS_WS_ID, $OPSINSIGHTS_WS_KEY)
            }

            # Check if Proxy Server should use
            if ((-not([STRING]::IsNullOrEmpty($Config.ProxyServerUri))))
            {
                $MMAgent.SetProxyUrl($Config.ProxyServerUri)
            } else {
                $MMAgent.SetProxyUrl('')
            }

            # Reload konfiguration
            $MMAgent.ReloadConfiguration()
        }
        catch {
            $_.Exception.Message
        }
    }
}

###########################################################################
# End
###########################################################################
<#
Author:			Arne Tiedemann
E-Mail:			Arne.Tiedemann@tiedemanns.info
Date:			2020-10-13
Description:    This script deploy the Microsoft Monitoring Agent and
                Microsoft Dependency Agent to Netlogon share of the domain
#>
###########################################################################
# Variables
###########################################################################
$DomainFQDN = $env:USERDNSDOMAIN

$Sources = @([PsCustomObject]@{
    Name = 'InstallDependencyAgent-Windows.exe'
    URL = 'https://aka.ms/dependencyagentwindows'
    Enabled = 0
    },
    [PsCustomObject]@{
    Name = 'MMASetup-AMD64.exe'
    URL = 'https://go.microsoft.com/fwlink/?LinkId=828603'
    Enabled = 1
    }
)

$PathRemote = ('\\{0}\netlogon\Env\Computer\Azure' -f $DomainFQDN)
$PathLocal = 'C:\Windows\Temp\Skaylink-Azure'


###########################################################################
# Functions
###########################################################################

###########################################################################
# Script
###########################################################################
if (-not(Test-Path -Path $PathLocal -ErrorAction SilentlyContinue))
{
    $null = New-Item -Path $PathLocal -Force -ItemType Directory
}

if (-not(Test-Path -Path $PathRemote -ErrorAction SilentlyContinue))
{
    $null = New-Item -Path $PathRemote -Force -ItemType Directory
}

# Download Sources
foreach($Source in $Sources | Where-Object { $_.Enabled -eq 1 })
{
    $File = ('{0}\{1}' -f $PathLocal, $Source.Name)
    try {
        Write-Host ('Download of file: {0}' -f $Source.Name) -NoNewline
        Invoke-WebRequest -Uri $Source.URL -OutFile $File -UseBasicParsing -ErrorAction Stop        
        Write-Host ' was successfully..' -ForegroundColor Green
    } catch {
        Write-Host ' was not successfull..' -ForegroundColor Red
    }
}

if (($Sources | Where-Object { $_.Name -eq 'MMASetup-AMD64.exe'}).Enabled)
{
    # Update Source of Monitoring Agent
    $DirDst = ('{0}\MMASetup-AMD64' -f $PathRemote)
    if (Test-Path -Path $DirDst -ErrorAction SilentlyContinue)
    {
        Remove-Item -Path $DirDst -Force -Recurse
    }

    # Unblock files
    Get-ChildItem -Path $PathLocal -File -Recurse | Unblock-File

    $File = ('{0}\{1}' -f $PathLocal,($Sources | Where-Object {$_.Name -like 'MMASetup*'}).Name)
    Start-Process -FilePath $File -ArgumentList ('/T:"{0}\MMASetup-AMD64\" /C /Q' -f $PathRemote)
}

# Copy to destination
Copy-Item -Recurse -Path ('{0}\*' -f $PathLocal) -Destination $PathRemote -Force

###########################################################################
# Finally
###########################################################################
# Cleaning Up the workspace

###########################################################################
# End
###########################################################################
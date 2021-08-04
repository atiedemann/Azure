<#
Author:			Arne Tiedemann
E-Mail:			Arne.Tiedemann@tiedemanns.info
Date:			2020-10-21
Description:	This Script encrypt the Workspace Key to use in Registry values
#>

###########################################################################
# Functions
###########################################################################
param(
    [Parameter(Mandatory)]
    $Workspacekey
)


function DecValue
{
    param(
        [Parameter(Mandatory)]
        $String
    )

    $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
    $DecodedText
}
function EncValue
{
    param(
        [Parameter(Mandatory)]
        $String
    )

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    $EncodedText
}
###########################################################################
# Script
###########################################################################
$Workspacekey = EncValue -String $Workspacekey
$WS_KeyDecrypted = DecValue -String $Workspacekey

Write-Host 'Values for your GPO environment variables:' -ForegroundColor Green
Write-Host (@"
WS_KEY secret = {0}
"@ -f $Workspacekey)


Write-Host "`nDecrypted values:" -ForegroundColor Yellow
Write-Host (@"
WS_KEY secret = {0}
"@ -f $WS_KeyDecrypted)

$Workspacekey | Set-Clipboard

Install-WindowsFeature "WDS-Deployment", "WDS-Transport", "DHCP" -IncludeManagementTools
#region Configure DHCP
$dhcpService = Get-Service DHCPServer
$dhcpService  | Stop-Service -Force
$dhcpService | Set-Service -StartupType Automatic
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters DisableRogueDetection 1 -Type DWord -Force
$dhcpService | Restart-Service -WarningAction SilentlyContinue
Set-DhcpServerSetting -ConflictDetectionAttempts 2
if ((Get-DhcpServerSetting).IsAuthorized) {
} else {
}

Get-DhcpServerv4Scope | Remove-DhcpServerv4Scope -Force -Confirm:$false

$dhcpScope = @{
    Name = "WDS MASLAB"
    StartRange = "10.31.231.100"
    EndRange = "10.31.231.199"
    SubnetMask = "255.255.255.0"
}

$scope = Add-DhcpServerv4Scope @DHCPScope -State InActive -PassThru -Confirm:$false
$scopeId = $scope.ScopeId.IPAddressToString

$defaultGateway = "10.31.231.1"
$scope | Set-DhcpServerv4OptionValue -Router $defaultGateway -Force -Confirm:$false

$DnsServer = "8.8.8.8"
$scope | Set-DhcpServerv4OptionValue -DnsDomain "AzureStack.Lab" -DnsServer $DnsServer
Get-DhcpServerv4Scope | Set-DhcpServerv4Scope -State Active
#endregion

#region Configure WDS
$WDSRemInstallFolder = "$env:SystemDrive\RemoteInstall"
$wdsstate = wdsutil /Verbose /Get-Server /Show:All
$PropertyName = 'WDS operational mode'
$PropertyPattern = "$PropertyName`: (.*?)\r"

if ($wdsstate -match $PropertyPattern) {
    return $matches[1]
    Write-Host $matches[0]
    Write-Host $matches[1]
} 


if ($wdsOperationalMode -ne 'Not Configured') {
    $null = wdsutil /verbose /Uninitialize-Server
} else {
}

if (Test-Path $WDSRemInstallFolder) {
    rmdir $WDSRemInstallFolder -Recurse -Force
}

$null = wdsutil /verbose /Initialize-Server /RemInst:$WDSRemInstallFolder /Standalone
$null = wdsutil /verbose /Start-Server
$null = wdsutil /verbose /Set-Server /AnswerClients:All /PxePromptPolicy /Known:NoPrompt /New:NoPrompt /UseDHCPPorts:No /DHCPOption60:Yes
$null = wdsutil /verbose /Set-Server /DHCPOption60:Yes

$NewWDSToolkitScript = Get-Content C:\DeployAzureStack\Scripts\DeployAzureStackPOC.ps1 -Raw
$NewWDSToolkitScript = $NewWDSToolkitScript.Replace('[DVMIP]','<WDS-IP>')
$NewWDSToolkitScript = $NewWDSToolkitScript.Replace('[DVMUserName]','AZURESTACK\maswds')
$NewWDSToolkitScript = $NewWDSToolkitScript.Replace('[DVMPassword]','<PASSWORD>')

$bootImagePath =  "$env:SystemDrive:\DeployAzureStack\BootImage\boot.wim"
$mountPath = [IO.Path]::GetTempFileName()
Remove-Item $mountPath -Recurse -Force
$null = mkdir $mountPath -Force
$mountedImages = Get-WindowsImage -Mounted -Verbose:$false
if ($mountedImages) {
    $null = $mountedImages | % { Dismount-WindowsImage -Path $_.MountPath -Discard -Verbose:$false}
}
$null = Mount-WindowsImage -Index 1 -ImagePath $bootImagePath -Path $mountPath -Verbose:$false
Set-Content -Value $NewWDSToolkitScript -Path "$mountPath\DeployAzureStackPOC.ps1" -Force 
Copy-Item C:\DeployAzureStack\Scripts\DeployAzureStackPOC.psm1 $mountPath -Force  
Copy-Item C:\DeployAzureStack\BootImage\startnet.cmd $mountPath\windows\system32 -Force

$null = Dismount-WindowsImage -Path $mountPath -Save -Verbose:$false
$null = Remove-WdsBootImage -ImageName "HPE MAS PE" -Architecture X64
$null = Import-WdsBootImage -Path $BootImagePath -NewImageName "HPE MAS PE"
net localgroup administrators AZURESTACK\maswds /add
#endregion
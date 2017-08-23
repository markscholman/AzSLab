$NETWORK_WAIT_TIMEOUT_SECONDS = 120
$WINPE_INSTALL_IMAGE_PATH = 'Z:\DeployAzureStack\Images\BootVHDX\WinPE.vhdx'
$HOST_IMAGE_PATH = 'Z:\DeployAzureStack\MASImage\CloudBuilder.vhdx'
$SPP_IMAGE_PATH = 'Z:\DeployAzureStack\SPPImage\SPP_latest.iso'
$VHD_IMAGE_PATH = 'Z:\DeployAzureStack\MASImage\CloudBuilder.vhdx'
$REMOTE_UNATTEND_FILE = 'Z:\DeployAzureStack\Unattend\MASPOC.xml'
$WINPE_LOG_PATH = 'Z:\DeployAzureStack\Logs'

$DVM_IP = '[DVMIP]'
$DVM_NAME = 'AZURESTACKWDS'

$DVM_USERNAME = '[DVMUserName]'
$DVM_PASSWORD = '[DVMPassword]'

try
{
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$winPEStartTime = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
Import-Module "$PSScriptRoot\DeployAzureStackPOC.psm1" -Force
cls
Write-LogMessage -Message "Starting Azure Stack POC Deployment at $winPEStartTime"
Write-LogMessage -Message "Creating credential object for WDS share"
$secureDVMPassword = ConvertTo-SecureString -String $DVM_PASSWORD -AsPlainText -Force
$dvmCredential = New-Object PSCredential -ArgumentList $DVM_USERNAME, $secureDVMPassword

$hostImagePath = $HOST_IMAGE_PATH
$winPEInstallImagePath = $WINPE_INSTALL_IMAGE_PATH
$winPEImageShareRoot = [System.IO.Path]::GetPathRoot($winPEInstallImagePath)
$remoteUnattendFile = $REMOTE_UNATTEND_FILE
$LogPath = $WINPE_LOG_PATH
$serialNumber = Get-WmiObject win32_bios | Select-Object -ExpandProperty SerialNumber
$serialNumber = $serialNumber.Replace(" ", "")
$logPath = "$LogPath\$serialNumber.log"

Write-LogMessage -Message "Initialize WinPE"
Set-WinPEDeploymentPrerequisites

$dvmDriveLetter = "Z"
$dvmShareRoot = "\\$DVM_NAME\C$"

Write-LogMessage -Message "Creating network drive $dvmDriveLetter to WDS share"
New-NetworkDrive -IPv4Address $DVM_IP -HostName $DVM_NAME -ShareRoot $dvmShareRoot -DriveLetter $dvmDriveLetter -Credential $dvmCredential

Write-LogMessage -Message "Configure boot and storage Disks."
"Configure boot and storage Disks." | Add-Content $logPath
$systemDrive = Set-DiskConfiguration -LogPath $logPath #-BootDiskConfigPath $bootDiskConfigPath

$vhdName = [System.IO.Path]::GetFileName($hostImagePath)
$vhdFilePath = "$systemDrive\$vhdName"

Write-LogMessage -Message "Copying File '$hostImagePath' to '$systemDrive'."
"Copying File '$hostImagePath' to '$systemDrive'." | Add-Content $logPath
$null = Copy-Item -LiteralPath $hostImagePath -Destination $systemDrive

$hostVHDName = [System.IO.Path]::GetFileName($hostImagePath)
Write-LogMessage -Message "Configure host for VHD Boot"
Set-HostVHDBoot -BootVHDFilePath "$systemDrive\$hostVHDName" -Un $remoteUnattendFile -SystemDrive $systemDrive -LogPath $logPath

Write-LogMessage -Message "Rebooting to full OS."
"Rebooting to full OS." | Add-Content $logPath
(Get-Date).ToString('yyyy/MM/dd HH:mm:ss') | Add-Content $logPath
wpeutil reboot
}
catch
{
    $_

    $_ | Add-Content $logPath
}
finally
{
    # Sleep to let the remote logs catch up
    Start-Sleep -Seconds 10
}

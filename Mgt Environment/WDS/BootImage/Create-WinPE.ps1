#run with the Deployment and Imaging Tools Environment (cmdlet)
copype.cmd amd64 D:\WinPe_amd64
Dism /mount-image /imagefile:D:\winpe_amd64\media\sources\boot.wim /index:1 /mountdir:D:\winpe_amd64\mount
Dism /Image:D:\winpe_amd64\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-WMI.cab"
Dism /Image:D:\winpe_amd64\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-NetFX.cab"
Dism /Image:D:\winpe_amd64\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-Scripting.cab"
Dism /Image:D:\winpe_amd64\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-PowerShell.cab"
Dism /Image:D:\winpe_amd64\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-DismCmdlets.cab"
Dism /Image:D:\winpe_amd64\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-StorageWMI.cab"

$startnet = Get-Content D:\WinPe_amd64\mount\windows\system32\startnet.cmd
$startnet += "`r`npowershell -c Set-ExecutionPolicy Unrestricted -Force"
$startnet += "`r`npowershell -NoExit -c X:\DeployAzureStackPOC.ps1"
$startnet

Set-Content -Value $startnet -Path "D:\WinPe_amd64\mount\windows\system32\startnet.cmd" -Force
#Set-Content -Value "wpeinit" -Path "D:\WinPe_amd64\mount\windows\system32\startnet.cmd" -Force

Dism /unmount-image /mountdir:D:\winpe_amd64\mount /commit
MakeWinPEMedia /ISO D:\WinPE_amd64 D:\WinPE_amd64\WinPE_amd64.iso



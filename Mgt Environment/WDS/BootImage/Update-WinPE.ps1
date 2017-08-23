#region Configure WinPE
$NewWDSToolkitScript = Get-Content C:\DeployAzureStack\Scripts\DeployAzureStackPOC.ps1 -Raw
$NewWDSToolkitScript = $NewWDSToolkitScript.Replace('[DVMIP]','<WDSVM-IP>')
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
Copy-Item C:\DeployAzureStack\Scripts\startnet.cmd $mountPath\windows\system32 -Force

$null = Dismount-WindowsImage -Path $mountPath -Save -Verbose:$false
$null = Remove-WdsBootImage -ImageName "HPE MAS PE" -Architecture X64
$null = Import-WdsBootImage -Path $BootImagePath -NewImageName "HPE MAS PE"
#endregion
New-Item -Path C:\Install\Scripts -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
		
$SqlAgName = "ASLABSQL01"
$SQLAGIP = "10.31.231.41"
$PrimSMA = "ASLABSMA01"
$SMAWebAccount = "AZURESTACK\admsma"
$SMAWebPwd = "<PASSWORD>"
$SMAREGUser = "admsmareg"
$SMAREGPWD = "<PASSWORD>"
		
Write-Host -ForegroundColor Cyan "Waiting for SQL to be available"
$node = "down"
while ($node -ne "up") {
	$testnode = Test-NetConnection -ComputerName $SQLAGIP -Port 1433
	if ($testnode.TcpTestSucceeded -eq $false) {
		Write-Host -ForegroundColor Cyan "Cannot reach $SqlAgName yet. Sleeping ..."
		Start-Sleep -Seconds 300
		Clear-DnsClientCache
	} else {
		$node = "up"
	}
				
}
Set-Location C:\Install\Orchestrator\SMA
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
Write-Host -ForegroundColor Cyan "Installing SMA Powershell Module"
Start-Process ".\PowershellModuleInstaller.msi" "/qb" -Wait
Write-Host -ForegroundColor Cyan "Installing Windows Features"
Install-WindowsFeature RSAT-AD-Tools,RSAT-DHCP,RSAT-RDS-Gateway -IncludeManagementTools -IncludeAllSubFeature
Install-WindowsFeature Web-Basic-Auth,Web-Windows-Auth,Web-Url-Auth,Web-Asp-Net45,NET-WCF-HTTP-Activation45 -IncludeManagementTools
Write-Host -ForegroundColor Cyan "Installing SMA Web Service "
if($env:ComputerName -eq $PrimSMA){
	Start-Process ".\WebServiceInstaller.msi" "/qb /L*v C:\Install\WebServiceInstaller.log CREATEDATABASE=YES APPOOLACCOUNT=$SMAWebAccount APPOOLPASSWORD=$SMAWebPwd SQLSERVER=$SqlAgName DATABASEAUTHENTICATION=Windows SQLDATABASE=SMA" -Wait
} else {
	Start-Process ".\WebServiceInstaller.msi" "/qb /L*v C:\Install\WebServiceInstaller.log CREATEDATABASE=NO APPOOLACCOUNT=$SMAWebAccount APPOOLPASSWORD=$SMAWebPwd SQLSERVER=$SqlAgName DATABASEAUTHENTICATION=Windows SQLDATABASE=SMA" -Wait
}
Start-Process "WorkerInstaller.msi" "/qb /L*v C:\Install\WorkerInstaller.log SERVICEACCOUNT=$SMAWebAccount SERVICEPASSWORD=$SMAWebPwd SQLSERVER=$SqlAgName DATABASEAUTHENTICATION=Windows SQLDATABASE=SMA" -Wait
net user $SMAREGUser $SMAREGPWD /add
WMIC USERACCOUNT WHERE "Name='$SMAREGUser'" SET PasswordExpires=FALSE
net localgroup smaAdminGroup $SMAREGUser /add
		
New-Item -Path HKLM:\SOFTWARE -Name BGInfo | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\BGInfo\" -Name "Role" -PropertyType String -Value "SMA Webservice / Worker" | Out-Null
Write-Host -ForegroundColor Cyan "Rebooting server in 10 seconds"
Start-Sleep -Seconds 10
Restart-Computer -Force
    

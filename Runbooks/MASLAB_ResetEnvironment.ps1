#region variables
$ILOs = "10.1.49.11","10.1.49.12","10.1.49.13","10.1.49.14","10.1.49.15","10.1.49.16","10.1.49.17","10.1.49.18","10.1.49.19","10.1.49.20","10.1.49.21","10.1.49.22","10.1.49.23","10.1.49.24","10.1.49.25","10.1.49.26","10.1.49.27","10.1.49.28","10.1.49.29","10.1.49.30","10.1.49.31","10.1.49.32","10.1.49.33","10.1.49.34","10.1.49.35","10.1.49.36","10.1.49.37","10.1.49.38","10.1.49.39","10.1.49.40","10.1.49.42","10.1.49.43","10.1.49.44","10.1.49.45","10.1.49.46"
$serverIpAddresses = "10.1.41.101","10.1.41.102","10.1.41.103","10.1.41.104","10.1.41.105","10.1.41.106","10.1.41.107","10.1.41.108","10.1.41.109","10.1.41.110","10.1.41.111","10.1.41.112","10.1.41.113","10.1.41.114","10.1.41.115","10.1.41.116","10.1.41.117","10.1.41.118","10.1.41.119","10.1.41.120","10.1.41.121","10.1.41.122","10.1.41.123","10.1.41.124","10.1.41.125","10.1.41.126","10.1.41.127","10.1.41.128","10.1.41.129","10.1.41.130","10.1.41.132","10.1.41.133","10.1.41.134","10.1.41.135","10.1.41.136"
#endregion

#region Credentials
$aadTenant = 'maslab1.onmicrosoft.com'
$aadAdminUser = 'serviceadmin@maslab1.onmicrosoft.com'
$aadAdminPassword = '<PASSWORD>'
$aadDelegatedAdminUser = 'delegatedadmin@maslab1.onmicrosoft.com'
$aadDelegatedAdminPassword = '<PASSWORD>'
$aadTenantUser = 'tenantuser@maslab1.onmicrosoft.com'
$aadTenantPassword = '<PASSWORD>'
#endregion

#region MasterJob
$ilocred = Get-AutomationPSCredential -Name 'BMCCred'
$LocalAdmincred = Get-AutomationPSCredential -Name 'LocalAdminCred'
$AzsAdmincred = Get-AutomationPSCredential -Name 'AzSAdminCred'
$LABShareAdminCredential =  Get-AutomationPSCredential -Name 'LabShareAdmin'
$aadAdminCred = New-Object System.Management.Automation.PSCredential($aadAdminUser, (ConvertTo-SecureString -AsPlainText -Force $aadAdminPassword))
$aadDelegatedAdminCred = New-Object System.Management.Automation.PSCredential($aadDelegatedAdminUser, (ConvertTo-SecureString -AsPlainText -Force $aadDelegatedAdminPassword))
$aadTenantCred = New-Object System.Management.Automation.PSCredential($aadTenantUser, (ConvertTo-SecureString -AsPlainText -Force $aadTenantPassword))

$jobs = @()
foreach ($ilo in $ILOs) {
    $jobs += Start-Job -ScriptBlock {
        Reset-PhysicalNode -iloIpAddress $using:ILO -ilocred $using:ilocred #-connectIloConsole
    }
}
$jobs | Receive-Job -Wait -AutoRemoveJob

$jobs = @()
foreach ($serverIpAddress in $serverIpAddresses) {
    $jobs += Start-Job -ScriptBlock {
        Wait-BaremetalDeployment -serverIpAddress $using:serverIpAddress -credential $using:LocalAdmincred
        Start-InstallAzureStack -serverIpAddress $using:serverIpAddress -AADTenant $using:AADTenant -LocalAdminCredential $using:LocalAdmincred -AADAdminCredential $using:aadAdminCred -AADDelegatedAdminCredential $using:aadDelegatedAdminCred -AADTenantCredential $using:aadTenantCred -Verbose
        Watch-AzureStackInstall -serverIpAddress $using:serverIpAddress -credential $using:LocalAdmincred
    }
}
$jobs | Receive-Job -Wait -AutoRemoveJob

#endregion

#region variables
$serverIpAddresses = "10.1.41.101","10.1.41.102","10.1.41.103","10.1.41.104","10.1.41.105","10.1.41.106","10.1.41.107","10.1.41.108","10.1.41.109","10.1.41.110","10.1.41.111","10.1.41.112","10.1.41.113","10.1.41.114","10.1.41.115","10.1.41.116","10.1.41.117","10.1.41.118","10.1.41.119","10.1.41.120","10.1.41.121","10.1.41.122","10.1.41.123","10.1.41.124","10.1.41.125","10.1.41.126","10.1.41.127","10.1.41.128","10.1.41.129","10.1.41.130","10.1.41.132","10.1.41.133","10.1.41.135","10.1.41.136"
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
$LocalAdmincred = Get-AutomationPSCredential -Name 'LocalAdminCred'
$AzsAdmincred = Get-AutomationPSCredential -Name 'AzSAdminCred'
$LABShareAdminCredential =  Get-AutomationPSCredential -Name 'LabShareAdmin'
$aadAdminCred = New-Object System.Management.Automation.PSCredential($aadAdminUser, (ConvertTo-SecureString -AsPlainText -Force $aadAdminPassword))
$aadDelegatedAdminCred = New-Object System.Management.Automation.PSCredential($aadDelegatedAdminUser, (ConvertTo-SecureString -AsPlainText -Force $aadDelegatedAdminPassword))
$aadTenantCred = New-Object System.Management.Automation.PSCredential($aadTenantUser, (ConvertTo-SecureString -AsPlainText -Force $aadTenantPassword))

$jobs = @()
foreach ($serverIpAddress in $serverIpAddresses) {
    $jobs += Start-Job -ScriptBlock {
        Start-AzureStackHostConfiguration -serverIpAddress $using:serverIpAddress -LocalAdminCredential $using:AzSAdminCred -AADAdminCredential $using:aadAdminCred -LABShareAdminCredential $using:LABShareAdminCredential
    }
}
$jobs | Receive-Job -Wait -AutoRemoveJob

#endregion



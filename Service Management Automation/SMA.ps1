Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

#set URL Endpoint
$smaEP = "https://aslabsma01"

#Set Credentials for BMC - ILO
$cred = Get-Credential ilo-admin
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "BMCCred" -Value $Cred

#Set Credentials for Local Administrator on installed hosts
$cred = Get-Credential LOCAL\Administrator
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "LocalAdminCred" -Value $Cred

#Set Credentials for Azure Stack Admin on installed hosts
$cred = Get-Credential AZURESTACK\azurestackadmin
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "AzSAdminCred" -Value $Cred

#Set Credentials for Azure Stack Admin on installed hosts
$cred = Get-Credential AZURESTACK\admdeploy
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "LabShareAdmin" -Value $Cred

#Set Credentials for Creating RDG users in AD
$cred = Get-Credential AZURESTACK\admad
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "ADAdminCred" -Value $Cred

#Set Credentials for users in AAD
$cred = Get-Credential admsma@asiccloud.onmicrosoft.com
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "AADAdmin" -Value $Cred

#Set Credentials for Sendgrid mailservice
$cred = Get-Credential mark@markscholman.com #azure_0e827f835b5f538f22f9d028ba57d87d@azure.com
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "SendGridCred" -Value $Cred

#Set Credentials for SQL SA Account
$cred = Get-Credential sa
Set-SmaCredential -WebServiceEndpoint $smaEP -Name "SQLAdmin" -Value $Cred

#Set Variable for mail server
Set-SmaVariable -Name "SQLServer" -Value "ASLABSQL01" -WebServiceEndpoint $smaEP

#Set Variable for mail server
Set-SmaVariable -Name "MailServer" -Value "smtp.office365.com" -WebServiceEndpoint $smaEP

#Set Variable for Mail from adress
Set-SmaVariable -Name "SendGridMailFrom" -Value "donotreply@asic.cloud" -WebServiceEndpoint $smaEP

#Set Variable for Mail from Name
Set-SmaVariable -Name "SendGridMailFromName" -Value "Azure Stack Lab Admin" -WebServiceEndpoint $smaEP

#Set Variable for Admin email adres
Set-SmaVariable -Name "AdminEmail" -Value "mark@azurestack.nl" -WebServiceEndpoint $smaEP

#Set Variable for remote desktop gateway url
Set-SmaVariable -Name "RDGatewayURL" -Value "lab.asic.cloud" -WebServiceEndpoint $smaEP

#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\ResetAndAssignHost.ps1" -Tags "Provisioning" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\StartAndAssignHost.ps1" -Tags "Provisioning" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\CreatePortalAccount.ps1" -Tags "Provisioning" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\Task_AccountManagement.ps1" -Tags "Tasks" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\Task_HandleExpiredServers.ps1" -Tags "Tasks" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\MASLAB_ResetEnvironment.ps1" -Tags "MASLAB" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
#import runbook
$runbook = Import-SmaRunbook -Path "..\Runbooks\MASLAB_HostConfig.ps1" -Tags "MASLAB" -WebServiceEndpoint $smaEP 
Publish-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP

#remove runbooks
$runbook = Get-SmaRunbook -Name "ResetAndAssignHost" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP
$runbook = Get-SmaRunbook -Name "StartAndAssignHost" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP
$runbook = Get-SmaRunbook -Name "Task_HandleExpiredServers" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP
$runbook = Get-SmaRunbook -Name "CreatePortalAccount" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP
$runbook = Get-SmaRunbook -Name "Task_AccountManagement" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP
$runbook = Get-SmaRunbook -Name "MASLAB_ResetEnvironment" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP
$runbook = Get-SmaRunbook -Name "MASLAB_HostConfig" -WebServiceEndpoint $smaEP
Remove-SmaRunbook -id $runbook.RunbookID -WebServiceEndpoint $smaEP


#Runbook retrieval commands
Get-SmaRunbook -WebServiceEndpoint $smaEP | select runbookname
Get-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
Get-SmaRunbook -WebServiceEndpoint $smaEP | select RunbookName

#interact with a running job
Get-SmaJob -WebServiceEndpoint $smaEP | sort starttime| Select JobID, JobStatus,starttime, endTime #-Last 1
$job = "328e69fb-7f6e-4aea-991d-0807e1e1f068"
Get-SmaJob -Id $job -WebServiceEndpoint $smaEP
#Stop-SmaJob -Id $job -WebServiceEndpoint $smaEP
#Resume-SmaJob -Id $job -WebServiceEndpoint $smaEP
Get-SmaJobOutput -WebServiceEndpoint $smaEP -Id $job -Stream Any
(Get-SmaJobOutput -WebServiceEndpoint $smaEP -Id $job -Stream Any).StreamText


#Start a runbook
$runbook = Get-SmaRunbook -Name "Task_HandleExpiredServers" -WebServiceEndpoint $smaEP
$job = Start-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
Get-SmaJob -Id $job -WebServiceEndpoint $smaEP
(Get-SmaJobOutput -WebServiceEndpoint $smaEP -Id $job -Stream Any).StreamText

#Start a runbook
$runbook = Get-SmaRunbook -Name "Task_AccountManagement" -WebServiceEndpoint $smaEP
$job = Start-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP
Get-SmaJob -Id $job -WebServiceEndpoint $smaEP
(Get-SmaJobOutput -WebServiceEndpoint $smaEP -Id $job -Stream Any).StreamText

#Start a runbook
$runbook = Get-SmaRunbook -Name "ResetMASNode" -WebServiceEndpoint $smaEP
$job = Start-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP -Parameters @{"serverBMCIpAddress"="10.1.251.47"}
Get-SmaJob -Id $job -WebServiceEndpoint $smaEP
Get-SmaJobOutput -WebServiceEndpoint $smaEP -Id $job -Stream Output

#Start a runbook
$runbook = Get-SmaRunbook -Name "NewUser" -WebServiceEndpoint $smaEP
$job = Start-SmaRunbook -Id $runbook.RunbookID -WebServiceEndpoint $smaEP -Parameters @{"FirstName"="Mark";"LastName"="Scholman";"UserName"="mark.scholman";"emailAddress"="mark@markscholman.com";"ServerIpAddress"="10.1.101.101"}
Get-SmaJob -Id $job -WebServiceEndpoint $smaEP
Get-SmaJobOutput -WebServiceEndpoint $smaEP -Id $job -Stream Output

#Create the Runbook schedule
Get-SmaSchedule -WebServiceEndpoint $smaEP
#$runbook = Get-SmaRunbook -WebServiceEndpoint $smaep -Id $runbook.RunbookID

help Set-SmaSchedule -Examples | Out-GridView

#Start SMA Runbook on the schedule
$schedule = Set-SmaSchedule -WebServiceEndpoint $smaEP -Name DailyServerReset -ScheduleType DailySchedule -StartTime "5/21/2016 5:00:00 AM" -ExpiryTime "12/30/9999 11:00:00 PM" -DayInterval 1
$runbook = Get-SmaRunbook -Name "Task_HandleExpiredServers" -WebServiceEndpoint $smaEP
Start-SmaRunbook -Id $runbook.RunbookID -ScheduleName $schedule.Name -WebServiceEndpoint $smaEP


#Start SMA Runbook on the schedule
$schedule = Set-SmaSchedule -WebServiceEndpoint $smaEP -Name DailyAccountManagement -ScheduleType DailySchedule -StartTime "5/21/2016 1:00:00 AM" -ExpiryTime "12/30/9999 11:00:00 PM" -DayInterval 1
$runbook = Get-SmaRunbook -Name "Task_AccountManagement" -WebServiceEndpoint $smaEP
Start-SmaRunbook -Id $runbook.RunbookID -ScheduleName $schedule.Name -WebServiceEndpoint $smaEP
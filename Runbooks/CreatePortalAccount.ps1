[cmdletbinding()]
param(
    $FirstName,
    $LastName,
    $Email,
    $AmountOfDays
)
$AADAdmin = Get-AutomationPSCredential -Name 'AADAdmin'
Connect-MsolService -Credential $AADAdmin

#$FirstName = 'test'
#$LastName = 'account'
#$Email = 'mark@markscholman.com'
#$AmountOfDays = 5

$userPrincipalName = "$FirstName.$LastName`@asiccloud.onmicrosoft.com"
$password = Get-RandomPassword -length 8

$existingUser = Get-MsolUser -UserPrincipalName $userPrincipalName -ErrorAction SilentlyContinue
if ($existingUser) {
    Remove-MsolUser -UserPrincipalName $userPrincipalName -Force
}
$AADUser = New-MsolUser -UserPrincipalName $userPrincipalName -FirstName $FirstName -LastName $LastName -DisplayName "$FirstName $LastName" -PasswordNeverExpires $true -Password $password -AlternateEmailAddresses $Email
$mailCred = Get-AutomationPSCredential -Name 'SendGridCred'
$mailServer = Get-AutomationVariable -Name "MailServer"
$mailFrom = Get-AutomationVariable -Name "SendGridMailFrom"
$mailFromName = Get-AutomationVariable -Name "SendGridMailFromName"
$mailParams = @{
    To = "$FirstName $LastName <$Email>"
    From = "$mailFromName <$mailFrom>"
    Bcc = "$mailFromName <$mailFrom>"
    SMTPServer = $mailServer
    Credential = $mailCred 
    Subject = "Azure Stack Portal login"
    Body= @"
    Hi $FirstName,
    <br><br>
    Your account has been created.
    <br><br>
    Tenant Portal: https://portal.bellevue.asic.cloud
    <br>
    Username: $($AADUser.UserPrincipalName)
    <br>
    Password: $($AADUser.Password)
    <br><br>
    
    Best regards,
    <br>
    $mailFromName
    <br><br>
"@
    BodyAsHtml = $true
    UseSsl = $true
}
Send-MailMessage @mailParams

<#
$azEnv = Add-AzureStackAzureRmEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.bellevue.asic.cloud" 
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $AadTenant -Credential $AADAdmin
#>
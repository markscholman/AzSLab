#delete expired accounts
Delete-ExpiredUsers

#send email for almost expired accounts
$almostExpiredUsers = Get-AlmostExpiredUsers
$almostExpiredUsers | foreach -Process {
    $currentDate = Get-Date
    $expirationDate = $_.AccountExpirationDate
    $amountOfDays = ($expirationDate - $currentDate).Days

    $UserName = $_.Name
    $FirstName = $_.GivenName
    $LastName = $_.Surname
    $emailAddress = $_.mail

    $mailCred = Get-AutomationPSCredential -Name 'SendGridCred'
    $mailFrom = Get-AutomationVariable -Name "SendGridMailFrom"
    $mailServer = Get-AutomationVariable -Name "MailServer"
    $mailFromName = Get-AutomationVariable -Name "SendGridMailFromName"

    Write-Output "Sending expiration warning to [$UserName]."
    $mailParams = @{
        To = "$FirstName $LastName <$emailAddress>"
        From = "$mailFromName <$mailFrom>"
        Bcc = "$mailFromName <$mailFrom>"
        SMTPServer = $mailServer
        Credential = $mailCred 
        Subject = "[Expiration Warning] - Azure Stack Lab login"
        Body= @"
Hi $FirstName,
<br><br>
Your account is about to expire. Please backup any content from your system that you would like to keep.
Your account will expire after $AmountOfDays day(s). To see more information about your server go to https://lab.asic.cloud
<br><br>
If you need more time on your lab please send a email.
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
}
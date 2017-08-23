#delete expired accounts
Delete-ExpiredUsers

#send email for almost expired accounts
$almostExpiredUsers = Get-AlmostExpiredUsers
$almostExpiredUsers | foreach -Process {
 $currentDate = Get-Date
 $expirationDate = $_.AccountExpirationDate
 $amountOfDays = ($expirationDate - $currentDate).Days
 SendEmailMessage -UserName $_.Name -FirstName $_.GivenName -LastName $_.Surname -emailAddress $_.mail -AmountOfDays $amountOfDays
}
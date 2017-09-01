[cmdletbinding()]
param(
    $serverBMCIpAddress,
    $serverIPAddress,
    $FirstName,
    $LastName,
    $Email,
    $AmountOfDays,
    $InstallAzureStack
)
try {
    Write-Output "Start runbook Start and assign server"
    Write-Output "Retrieving credentals from SMA"
    $bmcCred = Get-AutomationPSCredential -Name 'BMCCred'
    $serverCred = Get-AutomationPSCredential -Name 'LocalAdminCred'
    Write-Output "Start Server [$serverBMCIpAddress]"
    Start-PcsvDevice -TargetAddress $serverBMCIpAddress -Credential $bmcCred -ManagementProtocol IPMI -Confirm:$false
    $count = 0
    while ($true) {
        $count++
        $result = Invoke-Command -ScriptBlock {
            $value = Test-Path C:\CloudDeployment -ErrorAction SilentlyContinue
            return $value
        } -ComputerName $serverIPAddress -Credential $serverCred -ErrorAction SilentlyContinue
        Write-Output "Waiting for server to come online - Step $count out of 15"
        if ($result -eq $true) {break;}
        if ($count -eq 15) {
            Write-Output "It took to long for the server to be available, cancel deployment and stop host."
            Stop-PcsvDevice -TargetAddress $serverBMCIpAddress -Credential $bmcCred -ManagementProtocol IPMI -Confirm:$false
            $notReachable = $true 
            break;
        }
        Start-Sleep -Seconds 300
    }
    if ($notReachable -eq $true) {
        Write-Error "Cannot reach the host in time, aborting and sending notification to admin"
        $mailCred = Get-AutomationPSCredential -Name 'SendGridCred'
        $mailServer = Get-AutomationVariable -Name "MailServer"
        $mailFrom = Get-AutomationVariable -Name "SendGridMailFrom"
        $mailFromName = Get-AutomationVariable -Name "SendGridMailFromName"
        $Adminmail =  Get-AutomationVariable -Name 'AdminEmail'
        $mailParams = @{
            To = "Admin <$Adminmail>"
            From = "$mailFromName <$mailFrom>"
            SMTPServer = $mailServer
            Credential = $mailCred 
            Subject = "Azure Stack host Start and Assign failed"
            Body= "Hi,
            <br><br>
            A host with bmc address $serverBMCIpAddress failed the assignment.
            <br><br>
            Best regards,
            <br>
            Azure Stack Automation Admin"
            BodyAsHtml = $true
        }
        Send-MailMessage @mailParams
        break;
    }

    $UserName = ("$FirstName.$LastName").Replace(" ","")
    $password = Get-RandomPassword -length 12

    Write-Output "Configure user [$UserName]"
    $paramsNewUser = @{
        FirstName = $FirstName
        LastName = $LastName
        emailAddress = $Email
        Password = $password
        AmountOfDays = $AmountOfDays
    }
    ConfigureUser @paramsNewUser


    Write-Output "Set password on server."
    $paramsResetPassword = @{
        serverIpAddress = $serverIPAddress
        newPassword = $Password
        serverCred = $serverCred
    }
    ResetServerPassword @paramsResetPassword

    Write-Output "Send mail to user [$UserName]."
    $paramsEmail = @{
        UserName = $UserName
        FirstName = $FirstName
        LastName = $LastName
        Password = $Password
        emailAddress = $Email
        ServerIpAddress = $serverIPAddress
        AmountOfDays = $AmountOfDays
    }
    SendEmail @paramsEmail


    if ($InstallAzureStack -eq "True") {
        Get-SQLVariables
        $serverUpdateQuery = @"
Declare @serverIp nvarchar(100) = '{0}'
SELECT Servers.IpAddress, Servers.Name, AzureADs.TenantName, AzureADs.ServiceAdminUser, AzureADs.ServiceAdminPassword ,AzureADs.TenantUser, AzureADs.TenantPassword
FROM Servers
INNER JOIN AzureADs
ON Servers.Name=AzureADs.ServerName
WHERE Servers.IpAddress=@serverIp
"@ -f $serverIPAddress
        $azuread = Invoke-SqlCmd -SQLServer $SQLServer -Database AzureStackLabDb -query $serverUpdateQuery -username $sauser -password $sapassword
        if ($azuread) {
            Write-Output "Install AzureStack."
            $AadAdminCred = New-Object pscredential ($($azuread.ServiceAdminUser),(ConvertTo-SecureString -AsPlainText -Force $($azuread.ServiceAdminPassword)))
            $AadTenantCred = New-Object pscredential ($($azuread.TenantUser),(ConvertTo-SecureString -AsPlainText -Force $($azuread.TenantPassword)))
            $serverCred = New-Object pscredential ("Administrator",(ConvertTo-SecureString -AsPlainText -Force $password))
            $paramsMASInstall = @{
                serverIpAddress = $serverIPAddress
                LocalAdminCredential = $serverCred
                AADAdminCredential = $AadAdminCred
                AADTenantCredential = $AadTenantCred
                AADTenant = $azuread.TenantName
            }
            Start-InstallAzureStack @paramsMASInstall

            $paramsWatchMASInstall = @{
                serverIpAddress = $serverIPAddress
                credential = $serverCred
            }
            Watch-AzureStackInstall @paramsWatchMASInstall
        } else {
            Write-Error "Cannot obtain Azure AD information"
        }
    }
    Write-Output "Finished runbook Start and assign server"

} catch {
    Write-Error $Error[0]
}
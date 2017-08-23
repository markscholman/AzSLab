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
    Write-Output "Start runbook Reset and assign server"
    $bmcCred = Get-AutomationPSCredential -Name 'BMCCred'
    $serverCred = Get-AutomationPSCredential -Name 'LocalAdminCred'

    $paramsResetMasHost = @{
        iloIpAddress = $serverBMCIpAddress
        iloCred = $bmcCred
    }
    Reset-PhysicalNode @paramsResetMasHost

    $paramsWaitBareMetal = @{
        serverIpAddress = $serverIPAddress
        credential = $serverCred
    }
    Wait-BaremetalDeployment @paramsWaitBareMetal

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
    Write-Output "Finished runbook Reset and assign server"
} catch {
    Write-Error $Error[0]
}
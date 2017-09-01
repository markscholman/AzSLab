$serverquery = "select * from dbo.servers"
$requestquery = "select * from dbo.requests"
$identityquery = "select [Id],[Email],[UserName],[FirstName],[LastName] from dbo.AspNetUsers"

Write-Output "Invoke SQL query against SQL server [$SQLServer]"
$requestresults = Invoke-SqlCmd -Database AzureStackLabDb -query $requestquery
$pendingrequest = $requestresults | Where-Object {($_.Status -eq 2) -and ($_.Entitystate -eq 0) } | sort RequestNumber
$serverresults = Invoke-SqlCmd -Database AzureStackLabDb -query $serverquery

Write-Output "Determine expired servers"
$datetime = (Get-Date).ToUniversalTime()
$serverstowipe = $serverresults | Where-Object {($_.InUse -eq $true) -and ($_.EndDate -le $datetime) -and ($_.Entitystate -eq 0) }
if ($serverstowipe) {
    foreach ($server in $serverstowipe) {
        try {
            $serverClearQuery = @"
Declare @serverName nvarchar(100) = '{0}'
Update Servers
SET InUse=1,UserId=NULL,StartDate=NULL,EndDate=NULL
WHERE Name=@serverName;
"@ -f $server.Name
            Invoke-SqlCmd -Database AzureStackLabDb -query $serverClearQuery
            if ($pendingrequest) {
                Write-Output "There are pending reuests, selecting the first one"
                $nextrequest = $pendingrequest | select -First 1
                Write-Output "Retrieving identity from the database"
                $identities = Invoke-SqlCmd -Database AzureStackLabIdentity -query $identityquery
                $identity = $identities | Where-Object {$_.UserName -eq $nextrequest.UserId}
                Write-Output "Wipe server [$($server.Name)] and assign it to [$($nextrequest.UserId)]"
                $params =  @{
                    serverBMCIpAddress = $server.BMCIpAddress
                    serverIPAddress = $server.IpAddress
                    FirstName = $identity.FirstName
                    LastName = $identity.LastName
                    Email = $identity.Email
                    AmountOfDays = $nextrequest.AmountOfDays
                    InstallAzurestack = $nextrequest.AzureStackPreInstalled
                }
                .\ResetAndAssignHost.ps1 @params
                $datenow = (Get-Date).ToUniversalTime()
                $enddate = $datenow.AddDays($pendingrequest.AmountOfDays)
                $serverUpdateQuery = @"
Declare @serverName nvarchar(100) = '{0}'
Update Servers
SET InUse=1,UserId='{1}',StartDate='{2}',EndDate='{3}'
WHERE Name=@serverName;
"@ -f $server.Name,$pendingrequest.UserId,$datenow.ToString('yyyy/MM/dd HH:mm:ss'),$enddate.ToString('yyyy/MM/dd HH:mm:ss')
                Invoke-SqlCmd -Database AzureStackLabDb -query $serverUpdateQuery
                $requestUpdateQuery = @"
Declare @requestId nvarchar(100) = '{0}'
Update Requests
SET IsProcessed=1,Status=3,DateProcessed='{1}',ServerName='{2}'
WHERE RequestId=@requestId;
"@ -f $pendingrequest.RequestId,$datenow.ToString('yyyy/MM/dd HH:mm:ss'),$server.Name
                Invoke-SqlCmd -Database AzureStackLabDb -query $requestUpdateQuery
            } else {
                Write-Output "No pending requests wipe server [$($server.Name)]"
                $bmcCred = Get-AutomationPSCredential -Name 'BMCCred'
                $serverCred = Get-AutomationPSCredential -Name 'LocalAdminCred'

                $paramsResetMasHost = @{
                    iloIpAddress = $server.BMCIpAddress
                    iloCred = $bmcCred
                }
                Reset-PhysicalNode @paramsResetMasHost

                $paramsWaitBareMetal = @{
                    serverIpAddress = $server.IpAddress
                    credential = $serverCred
                }
                Wait-BaremetalDeployment @paramsWaitBareMetal

                Start-Sleep -Seconds 60
                Write-Output "Turn off server [$($server.Name)]"
                Stop-PcsvDevice -TargetAddress $server.BMCIpAddress -Credential $bmcCred -ManagementProtocol IPMI -Confirm:$false
                $serverUpdateQuery = @"
Declare @serverName nvarchar(100) = '{0}'
Update Servers
SET InUse=0
WHERE Name=@serverName;
"@ -f $server.Name
                Invoke-SqlCmd -Database AzureStackLabDb -query $serverUpdateQuery

            }
        } catch {
            Write-Error $Error[0]
        }
    }
} else {
    Write-Output "No servers to wipe!"
}
Write-Output "Finished!"
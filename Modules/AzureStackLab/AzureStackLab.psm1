if(-not $scriptLog) {
    $scriptLog = "$env:SystemDrive\Logs-MASLAB\Script.$(Get-Date -Format yyyy-MM-dd.hh-mm-ss).log"
    $null = New-Item -Path $scriptLog -ItemType File -Force
}

function Get-SQLVariables {
    $Global:SQLServer = "ASLABSQL01"
    $Global:sauser = "sa"
    $Global:sapassword = "<PASSWORD>"
}

function Write-VerboseLog {
  [CmdletBinding()]
  param ( 
    [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [String] $Message
  )

  $ErrorActionPreference = 'Stop'

  "Verbose: $Message" | Out-File $scriptLog -Append
  Write-Verbose $Message -Verbose
}

function Write-WarningLog {
  [CmdletBinding()]
  param ( 
    [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [String] $Message
  )

  $ErrorActionPreference = 'Stop'

  "Warning: $Message" | Out-File $scriptLog -Append
  Write-Warning $Message
}

function Write-TerminatingErrorLog {
  [CmdletBinding()] 
  param ( 
    [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [object] $Message
  )

  $ErrorActionPreference = 'Stop'

  # Write Error: line seperately otherwise out message will not contain stack trace
  "Error:" | Out-File $scriptLog -Append
  $Message | Out-File $scriptLog -Append

  throw $Message
}

function Write-LogMessage {
  <#
      .SYNOPSIS
      Writes a log message in the console.
      .DESCRIPTION
      See the Synopsis. It requires the Message parameter.
      .EXAMPLE
      Write-LogMessage -SystemName 'localhost' -Message "My message."
      This command writes "My Message" to the console output.
      .EXAMPLE
      Write-LogMessage -Message "My other message."
      This command writes "My other Message" to the console output.
  #>
  [cmdletbinding()]
  param
  (
    [string]$SystemName = $env:COMPUTERNAME,
    [object]$Message,
	$logPath = $scriptLog,
	[string]$MessageType
  )

  BEGIN {}
  PROCESS {
    Write-Verbose "Writing log message"
    #write-host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline
    #write-host ' - [' -ForegroundColor White -NoNewline
    #write-host $systemName -ForegroundColor Yellow -NoNewline
    #write-Host "]::$($message)" -ForegroundColor White
	switch ($MessageType) {
		"Error" {
			Write-TerminatingErrorLog -Message $Message
		}
		"Warning" {
			Write-WarningLog -Message $Message
		}
		"Verbose" {
			Write-VerboseLog -Message $Message
		}
		default {
			#Add-Content -Path $logPath "$((Get-Date).ToShortTimeString()) - [$SystemName]::$($Message)"
			Write-Output ('{0} - [{1}]::{2}' -f ((Get-Date).ToShortTimeString()),$systemName,$message)
		}
	}
  }
  END {}
}

function Reset-PhysicalNode {
param(
    $iloIpAddress,
    $iloCred,
    [switch]$connectIloConsole
)

    Write-LogMessage -Message "Stop server [$iloIpAddress]"
    Stop-PcsvDevice -TargetAddress $iloIpAddress -Credential $ilocred -ManagementProtocol IPMI -Confirm:$false
    Start-Sleep -Seconds 3
    Write-LogMessage -Message "Set PXE boot for next startup on server [$iloIpAddress]"
    Set-PcsvDeviceBootConfiguration -TargetAddress $iloIpAddress -Credential $ilocred -ManagementProtocol IPMI -OneTimeBootSource "CIM:Network:1"
    Start-Sleep -Seconds 3
    Write-LogMessage -Message "Start Server [$iloIpAddress]"
    Start-PcsvDevice -TargetAddress $iloIpAddress -Credential $ilocred -ManagementProtocol IPMI -Confirm:$false
    if ($connectIloConsole) {
        Start-Process "$PSScriptRoot\ILO\HPLOCONS.exe" -ArgumentList "-addr $iloIpAddress -name $($ilocred.UserName) -password $($ilocred.GetNetworkCredential().password)"
        Write-LogMessage -Message "Connected to ILO Console [$iloIpAddress]"
        Start-Sleep -Seconds 1
    }
}

function Wait-BaremetalDeployment {
[cmdletbinding()]
param(
	$serverIpAddress,
	$credential
)
$endTime = (Get-Date).AddMinutes(45)
Write-LogMessage -Message "[$serverIpAddress] - Waiting for baremetal deployment to finish."
do {
    if (Test-Connection $serverIpAddress -Quiet -Count 1) {
            $session = $null
            try {
                $session = New-PSSession -ComputerName $serverIpAddress -Credential $credential -ErrorAction SilentlyContinue
            } catch {
                if ($session) {
                    Write-LogMessage -Message "Caught exception after session to new OS was created: $_"
                    Remove-PSSession $session -ErrorAction SilentlyContinue
                    $session = $null
                }
                $global:error.RemoveAt(0)
            }

            if ($session) {
                $isNewDeployment = Invoke-Command -Session $session {
                    Test-Path "$env:SystemDrive\SetupComplete.txt"
                }

                if ($isNewDeployment)
                {
                    Write-LogMessage -Message "[$serverIpAddress] - Finished the OS deployment."
                }
            }
        }


    if ($isNewDeployment) { break }
	Write-LogMessage -Message "[$serverIpAddress] - Waiting till [$endTime] for baremetal deployment... Sleeping 60 seconds."
    Start-Sleep -Seconds 60

} until ([DateTime]::Now -gt $endTime)

if ($isNewDeployment) {
    Write-LogMessage -Message "[$serverIpAddress] - Bare metal deployment has completed."
} else {
    Write-LogMessage -Message "[$serverIpAddress] - Bare metal deployment has completed." -MessageType "Error"
}

}

function Start-InstallAzureStack {
[cmdletbinding()]
param(
    $serverIpAddress,
    $LocalAdminCredential,
    $AADAdminCredential,
    $AADDelegatedAdminCredential,
    $AADTenantCredential,
    $AADTenant
)
    $ip = $serverIpAddress.Split('.')
    $Gateway = "$($ip[0]).$($ip[1]).$($ip[2]).1"
    Write-LogMessage -Message "[$serverIpAddress] - Prepare host for Azure Stack installation."
    Write-LogMessage -Message "[$serverIpAddress] - Start Azure Stack installation has been triggered."
    Invoke-Command -ScriptBlock {
    param($LocalAdminCredential,$AADAdminCredential,$AADDelegatedAdminCredential,$AADTenantCredential,$AADTenant,$serverIpAddress,$Gateway)
        $LocalAdminPassword = $LocalAdminCredential.GetNetworkCredential().Password
        $AADAdminUser = $AADAdminCredential.UserName
        $AADAdminPassword = $AADAdminCredential.GetNetworkCredential().Password
        $AADDelegatedAdminUser = $AADDelegatedAdminCredential.UserName
        $AADDelegatedAdminPassword = $AADDelegatedAdminCredential.GetNetworkCredential().Password
        $AADTenantUser = $AADTenantCredential.UserName
        $AADTenantPassword = $AADTenantCredential.GetNetworkCredential().Password
        
        $installscript = @'
cd C:\CloudDeployment\Setup
$adminpass = ConvertTo-SecureString '{0}' -AsPlainText -Force 
$aadpass = ConvertTo-SecureString '{1}' -AsPlainText -Force 
$aadcred = New-Object System.Management.Automation.PSCredential ('{2}', $aadpass) 
.\InstallAzureStackPOC.ps1 -AdminPassword $adminpass -InfraAzureDirectoryTenantAdminCredential $aadcred -InfraAzureDirectoryTenantName "{3}"
'@ -f $LocalAdminPassword, $AADAdminPassword, $AADAdminUser, $AADTenant
        $installscript | Out-File C:\CloudDeployment\InstallAzurestack.ps1 -Force
        if ($AADDelegatedAdminCredential) {
            $logininfo = @'
Service Administrator:
{0}
{1}

Delegated Serviceadministrator:
{4}
{5}

Tenant User:
{2}
{3}

'@ -f $AADAdminUser, $AADAdminPassword, $AADTenantUser, $AADTenantPassword, $AADDelegatedAdminUser, $AADDelegatedAdminPassword
        } else {
            $logininfo = @'
Service Administrator:
{0}
{1}

Tenant User:
{2}
{3}

'@ -f $AADAdminUser, $AADAdminPassword, $AADTenantUser, $AADTenantPassword
        }
        $logininfo | Out-File C:\Users\Public\Desktop\AzureStackLoginInfo.txt -Force
        $WinLogonRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
	    Set-ItemProperty $WinLogonRegPath "DefaultUsername" -Value "Administrator"
	    Set-ItemProperty $WinLogonRegPath "DefaultPassword" -Value "$LocalAdminPassword"
	    Set-ItemProperty $WinLogonRegPath "AutoAdminLogon" -Value "1"
        Set-ItemProperty $WinLogonRegPath "AutoLogonCount" -Value "1"
        $RunOnceRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        Set-ItemProperty $RunOnceRegPath "InstallAzureStack" -Value "powershell.exe -file C:\CloudDeployment\installazurestack.ps1 -WindowStyle Normal -NoLogo -NoProfile"
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        Get-NetAdapter | Where-Object {$_.Status -eq "Disconnected"} | Disable-NetAdapter -Confirm:$false
        Get-NetAdapter | Where-Object {$_.LinkSpeed -eq '1 Gbps'} | Disable-NetAdapter -Confirm:$false
        $firstAdapter = Get-NetIPAddress | Where-Object {$_.IPv4Address -eq $serverIpAddress} | Select-Object -ExpandProperty InterfaceIndex
        Get-NetAdapter | Where-Object InterfaceIndex -NotContains $firstAdapter | Disable-NetAdapter -Confirm:$false
        Get-NetAdapter -InterfaceIndex $firstAdapter | Rename-NetAdapter -NewName "MAS_Uplink"
        Remove-NetIPAddress -InterfaceAlias "MAS_Uplink" -Confirm:$false
        $null = New-NetIPAddress -InterfaceAlias "MAS_Uplink" -IPAddress $serverIpAddress -PrefixLength 24 -DefaultGateway $Gateway -AddressFamily IPv4 -Confirm:$false
        Set-DnsClientServerAddress -InterfaceAlias "MAS_Uplink" -ServerAddresses 8.8.8.8 -Confirm:$false
        Start-Sleep -Seconds 300
        Rename-Computer -NewName AZS-HVN01 -Restart
    } -ComputerName $serverIpAddress -Credential $LocalAdminCredential -ArgumentList $LocalAdminCredential,$AADAdminCredential,$AADDelegatedAdminCredential,$AADTenantCredential,$AADTenant,$serverIpAddress,$Gateway
}

function Watch-AzureStackInstall {
[cmdletbinding()]
param(
    $serverIpAddress,
    $credential
)
    Write-LogMessage -Message "[$serverIpAddress] - Check Azure Stack installation."
    $endTime = (Get-Date).AddMinutes(300)
    do {
        if (Test-Connection $serverIpAddress -Quiet -Count 1) {
            $session = $null
            try {
                $session = New-PSSession -ComputerName $serverIpAddress -Credential $credential -ErrorAction SilentlyContinue
            } catch {
                if ($session) {
                    Write-LogMessage -Message " Caught exception after session to new OS was created: $_"
                    Remove-PSSession $session -ErrorAction SilentlyContinue
                    $session = $null
                }
                $global:error.RemoveAt(0)
            }

            if ($session) {
                $result = Invoke-Command -ScriptBlock {
                    $null = New-Item -ItemType Directory C:\CloudDeployment\Logs\Temp -Force -ErrorAction SilentlyContinue
                    Copy-Item -Path C:\CloudDeployment\Logs\* -Destination C:\CloudDeployment\Logs\Temp\ -Force -ErrorAction Stop
                    Write-Verbose "Searching for line: Action: Action plan 'Deployment' completed. "
                    $successsearch = Select-String -Path  C:\CloudDeployment\Logs\Temp\*.log -pattern "Action: Action plan 'Deployment' completed."
                    Write-Verbose "Searching for line: Action: Stopping invocation of action plan. "
                    $failedsearch = Select-String -Path  C:\CloudDeployment\Logs\Temp\*.log -pattern "Stopping invocation of action plan."
                    Remove-Item  C:\CloudDeployment\Logs\Temp\ -Force -Recurse
                    $AzureStackInstall = "Running"
                    if ($successsearch.Matches.success) {
                        $AzureStackInstall = "Installed"
                    }
                    if ($failedsearch.Matches.success) {
                        $AzureStackInstall = "Failed"
                    }
                    return $AzureStackInstall

                } -Session $session -ErrorAction Stop
                Write-LogMessage -Message "[$serverIpAddress] - The Azure Stack installation status is: $result"
                Remove-PSSession $session -Confirm:$false -ErrorAction SilentlyContinue
                if ($result -eq "Installed") {break;}
                if ($result -eq "Failed") {
                    #handle failed deployments
                    $failedDeployment = $true
                    Write-Error "[$serverIpAddress] - Error Installing Azure Stack"
                    break;
                }
                if ($result -eq "Running") {
                    Write-LogMessage -Message "[$serverIpAddress] - Waiting for AzureStack to be Installed ... Waiting 60 seconds"
                }
            }
        }       
        Start-Sleep -Seconds 60
    } until ([DateTime]::Now -gt $endTime)

    if ([DateTime]::Now -gt $endTime -or $failedDeployment) {
        Write-LogMessage -Message "[$serverIpAddress] - Deployment of Azure Stack failed." -MessageType "Error"
    }

    if ($result -eq "Installed") {
        Write-LogMessage -Message "[$serverIpAddress] - Deployment of Azure Stack succeeded."
    }
    return $result
}

function Start-AzureStackHostConfiguration {
param(
    [ipaddress]$serverIpAddress,
    [pscredential]$LocalAdminCredential,
    [pscredential]$AADAdminCredential
)

    Write-LogMessage -Message "[$serverIpAddress] - Configure Azure Stack host."
    Invoke-Command -ScriptBlock {
    param(
        [ipaddress]$serverIpAddress,
        [pscredential]$LocalAdminCredential,
        [pscredential]$AADAdminCredential
    )
        #region Uninstall Powershell 2017 (Juli)
        Start-Process msiexec.exe -ArgumentList '/x "{F0952E40-484C-4C01-957B-416115F2F8E0}" /quiet' -Wait -ErrorAction SilentlyContinue
        #endregion

        #region Set Power Plan to High Performance
        Try {
            $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
            $CurrPlan = $(powercfg -getactivescheme).split()[3]
            if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
            #Write-LogMessage -Message "Power Plan set to High Performance." 
        } Catch {
            Write-Warning -Message "Unable to set power plan to high performance"
        }

        #endregion

        #region Set home page Azure Stack Admin Portal
        $path = 'HKCU:\Software\Microsoft\Internet Explorer\Main\'
        $name = 'start page'
        $value = 'https://portal.local.azurestack.external/'
        $null = Set-Itemproperty -Path $path -Name $name -Value $value
        #Write-LogMessage -Message "IE Homepage set to https://portal.local.azurestack.external/" 
        #endregion

        #region Set AD Password policy to 180 days
        Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 180.00:00:00 -Identity azurestack.local -Server AZS-DC01
        #endregion

        #region disable IE ESC and UAC
        function Disable-InternetExplorerESC {
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
            Stop-Process -Name Explorer -Force
            #Write-LogMessage -Message "IE Enhanced Security Configuration (ESC) has been disabled." 
        }
        function Enable-InternetExplorerESC {
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1 -Force
            Stop-Process -Name Explorer
            #Write-LogMessage -Message "IE Enhanced Security Configuration (ESC) has been enabled." 
        }
        function Disable-UserAccessControl {
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
            #Write-LogMessage -Message "User Access Control (UAC) has been disabled."     
        }
        Disable-UserAccessControl
        Disable-InternetExplorerESC
        #endregion

        #region Disable realtime scanning (Defender)
        Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisablePrivacyMode $true -DisableIntrusionPreventionSystem $true `
             -DisableScriptScanning $true -DisableArchiveScanning $true -DisableScanningMappedNetworkDrivesForFullScan $true -DisableIOAVProtection $true `
             -DisableEmailScanning $true -DisableScanningNetworkFiles $true -DisableBlockAtFirstSeen $true -DisableAutoExclusions $true
        #Write-LogMessage -Message "Realtime scanning has been disabled."  
        #endregion

        #region Copy files
        #Write-LogMessage -Message "Copying files to d:\"  

        $cred = New-Object -TypeName System.Management.Automation.PSCredential "AZURESTACK\admdeploy",(ConvertTo-SecureString -AsPlainText -Force 'Welcome01!')
        $z = New-PSDrive -Name InstallShare -PSProvider FileSystem -Root '\\10.1.100.43\labshare' -Credential $cred
        Copy-Item -Path \\10.1.100.43\LabShare\Training\ -Destination D:\ -Recurse -ErrorAction SilentlyContinue
        #Write-LogMessage -Message "Files have been copied."  
        #endregion

        #region Install Azure Stack Tools for RTM
        $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module -Name 'AzureRm.Bootstrapper' -Force
        Install-AzureRmProfile -profile '2017-03-09-profile' -Force 
        Install-Module -Name AzureStack -RequiredVersion 1.2.10 -Force
        Invoke-WebRequest -UseBasicParsing -Uri https://github.com/Azure/AzureStack-Tools/archive/master.zip -OutFile "$env:TEMP\master.zip"
        Expand-Archive "$env:TEMP\master.zip" -DestinationPath C:\ -Force
        Remove-Item "$env:TEMP\master.zip"
        $Folder = New-Item -ItemType Directory -Path ~\Documents\WindowsPowerShell\Modules -Force
        Get-ChildItem -Path C:\AzureStack-Tools-master -Directory | ForEach-Object -Process {
            if (Get-ChildItem -Path $_.FullName -Filter *.psm1) {
                $PSM1 = Get-ChildItem -Path $_.FullName -Filter *.psm1
                Copy-Item -Path $_.FullName -Destination "$($Folder.FullName)\$($PSM1.BaseName)" -Recurse
                New-ModuleManifest -Path "$($Folder.FullName)\$($PSM1.BaseName)\$($PSM1.BaseName).psd1" -RootModule $PSM1.BaseName
            }
        } 
        #endregion

        #region Configure Azure Stack environment
        $tenantName = $AADAdminCredential.UserName.Split('@')[1]
        $azEnv = Add-AzureRmEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.local.azurestack.external" 
        $AadTenant = Get-AzsDirectoryTenantID -AADTenantName $tenantName -EnvironmentName AzureStackAdmin
        $AdminArmEndpoint = $azEnv.ResourceManagerUrl
        $tenantArmEndpoint = "https://management.local.azurestack.external" #used in RP deployment

        #endregion

        #region Logon to Azure Stack RTM
        $aadCredential = New-Object System.Management.Automation.PSCredential("aadadmin@tenant.onmicrosoft.com", `
                         (ConvertTo-SecureString -String "password" -AsPlainText -Force))
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $AadTenant -Credential $AADAdminCredential
        #endregion 

        #region Register all RP's
        $null = Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider -Force
        #endregion

        #region Create Default Offer and Plan
        $PlanName = "Trial"
        $OfferName = "Trial"
        $RGName = "PlansandOffersRG"
        $Location = (Get-AzsLocation).Name

        $computeParams = @{
        Name = "computedefault"
        CoresLimit = 200
        AvailabilitySetCount = 10
        VirtualMachineCount = 50
        VmScaleSetCount = 10
        Location = $Location
        }

        $netParams = @{
        Name = "netdefault"
        PublicIpsPerSubscription = 500
        VNetsPerSubscription = 500
        GatewaysPerSubscription = 10
        ConnectionsPerSubscription = 20
        LoadBalancersPerSubscription = 500
        NicsPerSubscription = 1000
        SecurityGroupsPerSubscription = 500
        Location = $Location
        }

        $storageParams = @{
        Name = "storagedefault"
        NumberOfStorageAccounts = 20
        CapacityInGB = 2048
        Location = $Location
        }

        $kvParams = @{
        Location = $Location
        }

        $quotaIDs = @()
        $quotaIDs += (New-AzsNetworkQuota @netParams).ID
        $quotaIDs += (New-AzsComputeQuota @computeParams).ID
        $quotaIDs += (New-AzsStorageQuota @storageParams).ID
        $quotaIDs += (Get-AzsKeyVaultQuota @kvParams)

        New-AzureRmResourceGroup -Name $RGName -Location $Location
        $plan = New-AzsPlan -Name $PlanName -DisplayName $PlanName -ArmLocation $Location -ResourceGroupName $RGName -QuotaIds $QuotaIDs
        New-AzsOffer -Name $OfferName -DisplayName $OfferName -State Public -BasePlanIds $plan.Id -ResourceGroupName $RGName -ArmLocation $Location 
        #endregion

        #region Adding default image Windows Server 2016
        $ISOPath = "D:\Training\Images\en_windows_server_2016_x64_dvd_9718492.iso"
        New-AzsServer2016VMImage -ISOPath $ISOPath -Net35 $true -IncludeLatestCU -Location $regionName -CreateGalleryItem $true -Version Full
        #endregion

        <#
        #region Install SQL RP
        Set-Location 'D:\Training\PaaS\SQL'
        $vmLocalAdminPass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
        $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $vmLocalAdminPass)
        .\DeploySQLProvider.ps1 -DirectoryTenantID $AadTenant -AzCredential $AADAdminCredential -VMLocalCredential $vmLocalAdminCreds -ResourceGroupName "System.Sql" -VmName "SQLVM" -ArmEndpoint $AdminArmEndpoint -TenantArmEndpoint $tenantArmEndpoint

        #endregion

        #region Install App Service RP
        Set-Location 'D:\Training\PaaS\AppService'
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
        .\Create-AppServiceCerts.ps1 -pfxPassword (ConvertTo-SecureString -AsPlainText -Force '<PASSWORD>') 

        #endregion

        #region Install MySQL RP
        Set-Location 'D:\Training\PaaS\MySQL'
        $vmLocalAdminPass = ConvertTo-SecureString "" -AsPlainText -Force
        $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("mysqlrpadmin", $vmLocalAdminPass)
        .\DeployMySQLProvider.ps1 -DirectoryTenantID $AadTenant -AzCredential $AADAdminCredential -VMLocalCredential $vmLocalAdminCreds -ResourceGroupName "System.MySql" -VmName "SystemMySqlRP" -ArmEndpoint $AdminArmEndpoint -TenantArmEndpoint $tenantArmEndpoint
        #endregion
        #>
    } -ComputerName $serverIpAddress -Credential $LocalAdminCredential -ArgumentList $serverIpAddress, $LocalAdminCredential, $AADAdminCredential
}

function Start-AzureStackConsoleVMConfiguration {
param(
    [ipaddress]$serverIpAddress,
    [pscredential]$LocalAdminCredential,
    [pscredential]$AADAdminCredential
)
    Write-LogMessage -Message "[$serverIpAddress] - Configure Azure Stack Console VM."
    Invoke-Command -ScriptBlock {
    param($serverIpAddress,$LocalAdminCredential,$AADAdminCredential)
        $AzureStackVMAdmin = New-Object System.Management.Automation.PSCredential("AZURESTACK\AzureStackAdmin", $LocalAdminCredential.Password)
        Write-Output $AzureStackVMAdmin.UserName 
        Write-Output $AzureStackVMAdmin.GetNetworkCredential().Password
        Get-NetIPAddress
        Invoke-Command -VMName MAS-CON01 -ScriptBlock {
        param($serverIpAddress,$AzureStackVMAdmin,$AADAdminCredential)
            #region Set Power Plan to High Performance
            Try {
                    $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
                    $CurrPlan = $(powercfg -getactivescheme).split()[3]
                    if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
                    #Write-LogMessage -Message "Power Plan set to High Performance."
                } Catch {
                    Write-Warning -Message "Unable to set power plan to high performance"
                }

            #endregion

            #region Set home page
            $path = 'HKCU:\Software\Microsoft\Internet Explorer\Main\'
            $name = 'start page'
            $value = 'https://publicportal.local.azurestack.external'
            Set-Itemproperty -Path $path -Name $name -Value $value
            #Write-LogMessage -Message "IE Homepage set to https://publicportal.local.azurestack.external"
            #endregion

            #region disable IE ESC
            function Disable-InternetExplorerESC {
                $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
                $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
                Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
                Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
                Stop-Process -Name Explorer -Force
                #Write-LogMessage -Message "IE Enhanced Security Configuration (ESC) has been disabled."
            }
            function Enable-InternetExplorerESC {
                $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
                $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
                Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
                Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1 -Force
                Stop-Process -Name Explorer
                #Write-LogMessage -Message "IE Enhanced Security Configuration (ESC) has been enabled."
            }

            Disable-InternetExplorerESC
            #endregion

            #region Disable ESC
            function Disable-UserAccessControl {
                Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
                #Write-LogMessage -Message "User Access Control (UAC) has been disabled."    
            }
            Disable-UserAccessControl
            #endregion

            #region Disable realtime scanning (Defender)
            Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisablePrivacyMode $true -DisableIntrusionPreventionSystem $true `
                 -DisableScriptScanning $true -DisableArchiveScanning $true -DisableScanningMappedNetworkDrivesForFullScan $true -DisableIOAVProtection $true `
                 -DisableEmailScanning $true -DisableScanningNetworkFiles $true -DisableBlockAtFirstSeen $true -DisableAutoExclusions $true
            #Write-LogMessage -Message "Realtime scanning has been disabled." 
            #endregion

            #region Copy Lab files
            New-Item -ItemType Directory C:\Scripts -ErrorAction SilentlyContinue
            Set-Location C:\Scripts
            $cred = New-Object -TypeName System.Management.Automation.PSCredential "AZURESTACK\admdeploy",(ConvertTo-SecureString -AsPlainText -Force 'Welcome01!')
            $z = New-PSDrive -Name InstallShare -PSProvider FileSystem -Root '\\10.1.100.43\labshare' -Credential $cred
            Copy-Item -Path \\10.1.100.43\LabShare\Training\Labs -Destination C:\ -Recurse
            Copy-Item -Path \\10.1.100.43\labshare\Training\AzureStack-Tools-master -Destination C:\ -Recurse
            Copy-Item -Path '\\MAS-HNV01\D$\Training\Images\WindowsServer2016-1612.vhd' -Destination "C:\labs\day3\images\WindowsServer2016Standard-1612.vhd"
            #Write-LogMessage -Message "Lab files have been copied to c:\labs." 
            #endregion

            #region Uninstall Powershell 2017
            Start-Process msiexec.exe -ArgumentList '/x "{4275CC00-2797-40D5-9752-AD555CFDC806}" /quiet' -Wait
            #Start-Process msiexec.exe -ArgumentList '/x 6B7CD146E21BDB9418543494DF256518 /quiet' -Wait
            #endregion

            #region Install Azure Stack Tools for TP3
            #Write-LogMessage -Message "Installing Azure Stack Tools for TP3."  
            New-Item -ItemType Directory C:\Scripts -ErrorAction SilentlyContinue
            # Install the AzureRM.Bootstrapper module
            $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module -Name AzureRm.BootStrapper -Force
            # Installs and imports the API Version Profile required by Azure Stack into the current PowerShell session.
            Use-AzureRmProfile -Profile 2017-03-09-profile -Force
            Install-Module -Name AzureStack -RequiredVersion 1.2.9 -Force
            #Get-Module -ListAvailable | where-Object {$_.Name -like "Azure*"}
            Invoke-WebRequest -UseBasicParsing -Uri https://github.com/Azure/AzureStack-Tools/archive/master.zip -OutFile "$env:TEMP\master.zip"
            Expand-Archive "$env:TEMP\master.zip" -DestinationPath C:\ -Force
            Remove-Item "$env:TEMP\master.zip"
            $Folder = New-Item -ItemType Directory -Path ~\Documents\WindowsPowerShell\Modules -Force

            ###### ----- ****** TEMP RETRIEVE TOOLS FROM SHARE INSTEAD OF WEB  ****** --------- #############

            Get-ChildItem -Path C:\AzureStack-Tools-master -Directory | ForEach-Object -Process {
                if (Get-ChildItem -Path $_.FullName -Filter *.psm1) {
                    $PSM1 = Get-ChildItem -Path $_.FullName -Filter *.psm1
                    Copy-Item -Path $_.FullName -Destination "$($Folder.FullName)\$($PSM1.BaseName)" -Recurse
                    New-ModuleManifest -Path "$($Folder.FullName)\$($PSM1.BaseName)\$($PSM1.BaseName).psd1" -RootModule $PSM1.BaseName
                }
            } 
            #Write-LogMessage -Message " Azure Stack Tools for TP3 have been installed."  
            #endregion

            #region Configure Azure Stack environment
            $tenantName = $AADAdminCredential.UserName.Split('@')[1]
            $AadTenant = Get-AADTenantGUID -AADTenantName $tenantName
            # Use this command to access the administrative portal
            $azEnv = Add-AzureStackAzureRmEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.local.azurestack.external" 
            $AdminArmEndpoint = $azEnv.ResourceManagerUrl
            #endregion

            #region Logon to Azure Stack TP3
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $AadTenant -Credential $AADAdminCredential
            #endregion  
            
        } -Credential $AzureStackVMAdmin -ArgumentList $serverIpAddress,$AzureStackVMAdmin,$AADAdminCredential
    } -ComputerName $serverIpAddress -Credential $LocalAdminCredential -ArgumentList $serverIpAddress, $LocalAdminCredential, $AADAdminCredential

}

function ConfigureUser {
[cmdletbinding()]
param(
    $FirstName,
    $LastName,
    $Password,
    $emailAddress,
    $AmountOfDays
)
Write-Output "Retrieving AD credentals from SMA."
$AdCred = Get-AutomationPSCredential -Name 'ADAdminCred'
$UserName = ("$FirstName.$LastName").Replace(" ","")
Write-Output "Check if user exist."
$aduser = Get-ADUser -filter "SAMAccountName -like ""$UserName"""
if (!$aduser) {
    $userParams = @{
        AccountExpirationDate = ((Get-Date).AddDays($AmountOfDays + 1))
        Name = $username
        GivenName = $FirstName
        SurName = $LastName
        DisplayName = "$FirstName $LastName"
        EmailAddress = $emailAddress
        PasswordNeverExpires = 1 
        cannotchangepassword = 1 
        path = "OU=USR,OU=LAB,DC=AzureStack,DC=Lab" 
        enabled = 1 
        AccountPassword = (ConvertTo-SecureString -AsPlainText $Password -Force)
        Description = "Azure Stack Lab Account"
        Credential = $AdCred
    }
    Write-Output "Creating AD user [$UserName]"
    New-ADUser @userParams
    Write-Output "Adding user [$UserName] to the Remote Desktop Gateway Group."
    Add-ADGroupMember -Identity "RDG_Users" -Members $UserName -Credential $AdCred
    Write-Output "Finished - User [$UserName] Created and added to RD Gateway Group."
} else {
    Write-Output "Reset password for user [$UserName]"
    $userParams = @{
        Identity = $adUser.Name
        Credential = $AdCred
        NewPassword = ConvertTo-SecureString -AsPlainText $Password -Force
        Reset = $true
        Confirm = $false
    }
    Set-ADAccountPassword @userParams
    $aduser | Set-ADUser -AccountExpirationDate ((Get-Date).AddDays($AmountOfDays + 1)) -Credential $AdCred
    Write-Output "Finished - Password for User [$UserName]"
}
}

function Get-AlmostExpiredUsers {
    $allUsers = Get-ADUser -Filter * -SearchBase "OU=LAB,DC=AzureStack,DC=Lab" -Properties @('AccountExpirationDate','mail')
    $expiredUsers = @()
    $allUsers | foreach -Process {
        $currentDate = Get-Date
        $accountExpirationDate = $_.AccountExpirationDate
        if ((($currentDate.AddDays(5)) -ge $accountExpirationDate) -and ($accountExpirationDate -ne $null)) {
            $expiredUsers += $_
        }
    }
    return $expiredUsers
}

function Delete-ExpiredUsers {
    $allUsers = Get-ADUser -Filter * -SearchBase "OU=LAB,DC=AzureStack,DC=Lab" -Properties @('AccountExpirationDate','mail')
    $expiredUsers = @()
    $allUsers | foreach -Process {
        $currentDate = Get-Date
        $accountExpirationDate = $_.AccountExpirationDate
        if (($currentDate.Date -gt $accountExpirationDate.Date) -and ($accountExpirationDate -ne $null)) {
            $expiredUsers += $_
            Remove-ADUser $_.SamAccountName -Confirm:$false
        }
    }
    Write-Output $expiredUsers
}

function SendEmailMessage {
[cmdletbinding()]
param(
    $UserName,
    $FirstName,
    $LastName,
    $emailAddress,
    $AmountOfDays
)

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
    Subject = "{Expiration Warning] - Azure Stack Lab login"
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

function ResetServerPassword {
[cmdletbinding()]
param(
    $serverIpAddress,
    $newPassword,
    $serverCred
)
try {
    Write-Output "Reset server Administrator password on server [$serverIpAddress]"
    Invoke-Command -ScriptBlock {
        net user massupport Supp0rt17! /add
        WMIC USERACCOUNT WHERE "Name='massupport'" SET PasswordExpires=FALSE
        net localgroup Administrators massupport /add
        net user Administrator $using:newPassword
        Write-Host "Password successful reset"
    } -ComputerName $serverIpAddress -ArgumentList $newPassword -Credential $serverCred
} catch {
    Write-Error $Error[0]
}
}

function SendEmail {
[cmdletbinding()]
param(
    $UserName,
    $FirstName,
    $LastName,
    $Password,
    $emailAddress,
    $ServerIpAddress,
    $AmountOfDays
)

$mailCred = Get-AutomationPSCredential -Name 'SendGridCred'
$mailFrom = Get-AutomationVariable -Name "SendGridMailFrom"
$mailServer = Get-AutomationVariable -Name "MailServer"
$mailFromName = Get-AutomationVariable -Name "SendGridMailFromName"
$rdGatewayUrl = Get-AutomationVariable -Name "RDGatewayURL"

Write-Output "Generating tempory RDP file."
$rdpFile = Get-Content C:\Install\Scripts\MASLABHOST.rdp
#$rdpFile = $rdpFile.Replace("[USERNAME]","AZURESTACK\$UserName")
$rdpFile = $rdpFile.Replace("[IPADDRESS]",$ServerIpAddress)
$rdpFile = $rdpFile.Replace("[GATEWAYURI]",$rdGatewayUrl)
Set-Content C:\Install\Scripts\MASLAB-$UserName.rdp -Value $rdpFile -Force
Write-Output "Sending login information + RDP to user [$UserName]."
$mailParams = @{
    To = "$FirstName $LastName <$emailAddress>"
    From = "$mailFromName <$mailFrom>"
    Bcc = "$mailFromName <$mailFrom>"
    SMTPServer = $mailServer
    Credential = $mailCred 
    Subject = "Azure Stack Lab login"
    Attachments = "C:\Install\Scripts\MASLAB-$UserName.rdp"
    Body= @"
    Hi $FirstName,
    <br><br>
    Your account has been created / reset. You can use the attached RDP icon where the remote desktop gateway information is already supplied. Or if you use RDP tooling like RoyalTS or Devolutions RDM find here your information:
    <br><br>
    <h4>Remote Desktop Gateway:</h4>
    Server: $rdGatewayUrl
    <br>
    Username: $env:USERDOMAIN\$UserName
    <br>
    Password: $Password
    <br><br>
    <h4>Your server login:</h4>
    Username: Administrator (*1) 
    <br>
    Password: $Password
    <br><br> 
    Your account will expire after $AmountOfDays day(s). If you need more time on your lab please send a email.
    <br><br>
    Best regards,
    <br>
    $mailFromName
    <br><br>
    (*1)
    If you checked the "Azure Stack Pre-installed" checkbox during your request then your username is: AZURESTACK\azurestackadmin. And wait for at least 60 minutes before login as the Azure Stack installer is running and will reboot couple times. Once you are logged in you can track the installation progress.)
    <br>
    If your RDP icon attached to this mail is blocked, please log in to the website and connect using the "connect" button in your server details pane.
"@
    BodyAsHtml = $true
    UseSsl = $true
}
Send-MailMessage @mailParams
Write-Output "Finished. Removing temp RDP file."
Remove-Item "C:\Install\Scripts\MASLAB-$UserName.rdp" -Force
}

function Invoke-SqlCmd {
[cmdletbinding()]
param(
    $SQLServer,
    $Database,
    $query,
    $username,
    $password
)
    $result = Invoke-Command -ScriptBlock {
        $table = Invoke-SqlCmd -Database $using:Database -Query $using:query -Username $using:username -Password $using:password
        return $table
    } -ComputerName $SQLServer #-Credential $cred
    return $result
}

$ascii=$NULL;
For ($a=65;$a –le 90;$a++) {$ascii+=,[char][byte]$a }
For ($a=48;$a –le 57;$a++) {$ascii+=,[char][byte]$a }
For ($a=97;$a –le 122;$a++) {$ascii+=,[char][byte]$a }
Function Get-RandomPassword {
    Param(
    [int]$length=8,
    [string[]]$sourcedata = $ascii
    )

    For ($loop=1; $loop –le $length; $loop++) {
                $TempPassword+=($sourcedata | GET-RANDOM)
                }
    return $TempPassword + '!'
}

Export-ModuleMember -Function Write-LogMessage, Reset-PhysicalNode, Wait-BaremetalDeployment, Start-InstallAzureStack, Watch-AzureStackInstall, Start-AzureStackHostConfiguration, Start-AzureStackConsoleVMConfiguration,
SendEmail,Invoke-SqlCmd,ResetServerPassword,ConfigureUser,Get-RandomPassword,Get-SQLVariables,Get-AlmostExpiredUsers,Delete-ExpiredUsers,SendEmailMessage
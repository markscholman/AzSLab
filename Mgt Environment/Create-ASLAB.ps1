function Create-VM {
param(
    $ServerName = "ASLABWDS01",
    $Generation  = 2,
    $RAM = 2,
    $CPU = 1,
    $DatadisksCount = 0,
    $SwitchName = "MAS-LAB",
    $VLAN = 1000,
    $MasterVHD = "C:\Hyper-V\_MASTER\WS2016DC_G2_16-10.vhdx",
    $VMLocation = "C:\Hyper-V",
    $AdminPassword = "P@ssw0rd!",
    $IpAddress = "10.1.100.43/24",
    $IPDefaultGW = "192.168.5.1",
    $PrimDNS = "192.168.5.51",
    $SecDNS = "",
    [switch]$LabVM,
    [switch]$startvm
)
$vm = @{
    ServerName = $ServerName;
    Generation = $Generation;
    RAM = $RAM;
    CPU = $CPU;
    Datadisks = $DatadisksCount;
    SwitchName = $SwitchName;
    VLAN = $VLAN;
    MasterVHD = $MasterVHD;
    VMLocation = $VMLocation;
    LabVM = $LabVM;
    AdminPassword = $AdminPassword;
    IpAddress = $IpAddress;
    IPDefaultGW = $IPDefaultGW;
    PrimDNS = $PrimDNS;
    SecDNS = $SecDNS;
 }      
$ServerName = $vm.ServerName
$VMStorage = $vm.VMLocation
$Ipaddress = $vm.IpAddress
$IPDefaultGW = $vm.IPDefaultGW
$PrimDNS = $vm.PrimDNS
$SecDNS = $vm.SecDNS
$AdminPassword = $vm.AdminPassword
#region New Virtualmachine
Write-Host -ForegroundColor Cyan "  Creating $ServerName"
# Create New VM
New-VM -Path $vm.VMLocation -Name $vm.ServerName -Generation $vm.Generation -SwitchName $vm.SwitchName -Memory (1Gb * $vm.RAM) | Out-Null

#VM adjustments
if ($vm.LabVM -eq $false) {
    Set-VM -Name $vm.ServerName -StaticMemory -MemoryStartupBytes (1Gb * $vm.RAM) -ProcessorCount $vm.CPU
} else {
    Set-VM -Name $vm.ServerName -DynamicMemory -MemoryMaximumBytes (1Gb * $vm.RAM) -MemoryMinimumBytes 768MB -MemoryStartupBytes (1Gb * $vm.RAM) -ProcessorCount $vm.CPU
}

# Set VLAN
Write-Host -ForegroundColor Yellow "    Configuring VLAN for $ServerName"
Set-VMNetworkAdapterVlan -VMName $vm.ServerName -Access -VlanId $vm.VLAN

# Add Disk
Write-Host -ForegroundColor Yellow "    Copy / Configuring disks for $ServerName"
if ($vm.LabVM -eq $false) {
    $VHD = Copy-Item -Path $vm.MasterVHD -Destination "$VMStorage\$ServerName\$ServerName`_OS.vhdx" -Recurse -PassThru
} else {
    $VHD = New-VHD -Path "$VMStorage\$ServerName\$ServerName`_OS.vhdx" -ParentPath $vm.MasterVHD -Differencing
}
if (($vm.Generation -eq 1) -and ($vm.LabVM -eq $true)) {
    $OSdisk = Add-VMHardDiskDrive -VMName $vm.ServerName -path $VHD.path -ControllerType IDE -Passthru
} 
if (($vm.Generation -eq 2) -and ($vm.LabVM -eq $true)) {
    $OSdisk = Add-VMHardDiskDrive -VMName $vm.ServerName -path $VHD.Path -ControllerType SCSI -Passthru
}
if (($vm.Generation -eq 1) -and ($vm.LabVM -eq $false)) {
    $OSdisk = Add-VMHardDiskDrive -VMName $vm.ServerName -path $VHD -ControllerType IDE -Passthru
} 
if (($vm.Generation -eq 2) -and ($vm.LabVM -eq $false)) {
    $OSdisk = Add-VMHardDiskDrive -VMName $vm.ServerName -path $VHD -ControllerType SCSI -Passthru
}

#Add additonal disks
if ($vm.Datadisks -ge 1 ) {
    For ($i = 0 ; $i -lt $vm.Datadisks; $i++ ) {
        Write-Host -ForegroundColor Yellow "    Add additional disks for $ServerName"
        $program = New-VHD -Path "$VMStorage\$ServerName\$ServerName`_Data_$i.vhdx" -Dynamic -SizeBytes 127GB		
        Add-VMHardDiskDrive -Path $program.Path -VMName $vm.ServerName -ControllerType SCSI
    }
}
  
#Set Disk to first boot device
if ($vm.Generation -eq 1) {
    Set-VMBios -VMName $vm.ServerName -StartupOrder @("IDE","CD","LegacyNetworkAdapter","Floppy")
} else {
    Set-VMFirmware -VMName $vm.ServerName -FirstBootDevice $OSdisk
}

#Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $vm.ServerName #if you need to copy files in the VM enable this line

#endregion
#region customize vm
#Mountdisk to add some other magic
Write-Host -ForegroundColor Yellow "    Mounting OS disk $ServerName to copy data"
  $disk = Mount-VHD -Path $OSdisk.Path -Passthru
  $x = Get-Disk -Number $disk.Number | Get-Partition | Where-Object { $_.Size -gt 2GB }
  Get-Disk -Number $disk.Number | Set-Disk -IsOffline $false
  Set-Partition -PartitionNumber $x.PartitionNumber -NewDriveLetter T -DiskNumber $x.DiskNumber  -ErrorAction SilentlyContinue
  Start-sleep -Seconds 3
  $null = New-PSDrive -Name t -Root t:\ -PSProvider FileSystem
  $null = New-Item -Path 'T:\Install\Scripts' -ItemType Directory -ErrorAction SilentlyContinue
  $null = New-Item -Path 'T:\Windows\Setup\Scripts' -ItemType Directory -ErrorAction SilentlyContinue
@"
@echo off
if exist %SystemDrive%\unattend.xml del %SystemDrive%\unattend.xml
reg add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /t REG_SZ /d "Unrestricted" /f
reg add HKLM\SOFTWARE\Microsoft\ServerManager /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f
ipconfig.exe /registerdns
powershell.exe -command %WinDir%\Setup\Scripts\SetupComplete.ps1
"@ | Out-File T:\Windows\Setup\Scripts\SetupComplete.cmd -Encoding ascii
@'
New-Item -Path C:\Install\Scripts -ItemType Directory -ErrorAction SilentlyContinue
$drive = Get-WmiObject -Class win32_volume | ? {$_.Driveletter -eq "D:"}
if ($drive -ne $null -and $drive.DriveType -ne 3) {
    Set-WmiInstance -input $drive -Arguments @{ DriveLetter = "Z:"; Label = "DVD Drive" }
}
$disks = Get-Disk | Where-Object { $_.OperationalStatus -ne "Online" }
if ($disks -ne $null) {
    foreach ($disk in $disks) {
	    if ($disk | Where-Object OperationalStatus -eq Offline) {
		    $disk | Set-Disk -IsOffline $false
		    if ($disk.PartitionStyle -eq "RAW") {
			    $disk | Initialize-Disk -PartitionStyle GPT
		    }
		    if ($disk.IsReadOnly -eq $True) {
			    $disk | Set-Disk -IsReadOnly $False
		    }
		    $disk | New-Partition -UseMaximumSize -AssignDriveLetter |
		    Format-Volume -FileSystem NTFS -allocationunitsize 4096 -Force -Confirm:$false
	    }
    }
}
Get-NetFirewallRule RemoteDesktop-UserMode-In-TCP | Set-NetFirewallRule -Enabled True
Get-NetFirewallRule FPS-SMB-In-TCP | Set-NetFirewallRule -Enabled True
Remove-WindowsFeature Windows-Server-Antimalware-Features
Remove-Item "C:\Windows\Setup\Scripts\SetupComplete.cmd" -Force
Remove-Item "C:\Windows\Setup\Scripts\SetupComplete.ps1" -Force
'@ | Out-File T:\Windows\Setup\Scripts\SetupComplete.ps1 -Encoding ascii
@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ServerName</ComputerName>
            <RegisteredOrganization></RegisteredOrganization>
            <RegisteredOwner></RegisteredOwner>
        </component>
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$Ipaddress</IpAddress>
                    </UnicastIpAddresses>
                    <Identifier>Ethernet</Identifier>
                    <Routes>
                        <Route wcm:action="add">
                            <Identifier>1</Identifier>
                            <Prefix>0.0.0.0/0</Prefix>
                            <NextHopAddress>$IPDefaultGW</NextHopAddress>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$PrimDNS</IpAddress>
			            <IpAddress wcm:action="add" wcm:keyValue="2">$SecDNS</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <TimeZone>W. Europe Standard Time</TimeZone>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$AdminPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <RegisteredOrganization></RegisteredOrganization>
            <RegisteredOwner></RegisteredOwner>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
        </component>
    </settings>
</unattend>

"@ | Out-File T:\Unattend.xml -Encoding ascii
Write-Host -ForegroundColor Yellow "    Dismounting OS Disk $ServerName"
Dismount-VHD $OSdisk.Path
#endregion
if ($startvm) {
    Write-Host -ForegroundColor Yello "  Starting VM $ServerName"
    start-vm $vm.ServerName
}
Write-Host -ForegroundColor Yello "Finished creating VM $ServerName"

}
Create-VM -ServerName ASLABDC01 -IpAddress 10.31.231.46/24 -startvm
Create-VM -ServerName ASLABDC02 -IpAddress 10.31.231.47/24 -startvm
Create-VM -ServerName ASLABSQL01 -IpAddress 10.31.231.41/24 -CPU 4 -RAM 8 -DatadisksCount 3 -startvm
Create-VM -ServerName ASLABRDW01 -IpAddress 10.31.231.44/24 -startvm
Create-VM -ServerName ASLABWDS01 -IpAddress 10.31.231.43/24 -startvm
Create-VM -ServerName ASLABSMA01 -IpAddress 10.31.231.48/24 -CPU 2 -RAM 8 -startvm
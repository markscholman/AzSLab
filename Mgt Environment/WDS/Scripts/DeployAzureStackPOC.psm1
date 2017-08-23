$HostFile = "$Env:SystemRoot\System32\Drivers\Etc\Hosts" 
# Set manually if needed
$ENABLE_DEBUGGING = $false
$DEBUG_CONNECTION_TYPE = '[DebugConnectionType]'
$DEBUG_SERIAL_PORT = '[DebugSerialPort]'
$DEBUG_SERIAL_BAUD_RATE = '[DebugSerialBaudRate]'
$DEBUG_NET_PORT_MAP_STRING = '[DebugNetPortMapString]'
$DEBUG_NET_HOST_IP = '[DebugNetHostIP]'
$DEBUG_NET_KEY = '[DebugNetKey]'
$DEBUG_NET_BUS_PARAMS = '[DebugNetBusParams]'
$ENABLE_SERIAL_CONSOLE = $false
$CONSOLE_SERIAL_PORT = '[ConsoleSerialPort]'
$CONSOLE_SERIAL_BAUD_RATE = '[ConsoleSerialBaudRate]'

# Starts all the services needed to intialize deployment on win PE
function Set-WinPEDeploymentPrerequisites
{
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    if (-not (Get-Command wpeutil*)) {
        Write-Warning "This script is intended to be execute in WinPE only."
        return
    }

    $null = wpeutil InitializeNetwork
    $null = wpeutil EnableFirewall
    $null = wpeutil WaitForNetwork

    $null = Start-Service -Name LanmanWorkstation
}

function New-NetworkDrive
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]
        $IPv4Address,

        [Parameter(Mandatory=$true)]
        [string]
        $HostName,

        [Parameter(Mandatory=$true)]
        [string]
        $ShareRoot,

        [Parameter(Mandatory=$true)]
        [PSCredential]
        $Credential,

        [Parameter(Mandatory=$true)]
        [string]
        $DriveLetter
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # Add Host Entry
    $hostEntry = "$IPv4Address     $HostName"

    if(-not (Get-Content $HostFile).Contains($hostEntry))
    {
        Write-LogMessage -Message "Add host entry: '$hostEntry'."
        $hostEntry | Out-File -FilePath $HostFile -Append -Encoding ascii
    }

    # Set PS Drive
    if(-not (Get-PSDrive | ? Name -EQ $DriveLetter))
    {
        Write-LogMessage -Message "Create PSDrive '$DriveLetter' to '$ShareRoot'."
        New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $ShareRoot -Credential $Credential -Persist -Scope Global
    }
}

# Returns back the SystemDrive
function Set-DiskConfiguration
{
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $LogPath,

        [Parameter(Mandatory=$false)]
        [string]
		$BootDiskConfigPath
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    (Get-Date).ToString('yyyy/MM/dd HH:mm:ss') | Add-Content $logPath
    "Reset the disks and clean them of all data." | Add-Content $logPath
    Write-LogMessage -Message "Reset the disks and clean them of all data."
    Get-Partition | Remove-Partition -Confirm:$false -ErrorAction SilentlyContinue
    # account for change in Reset-PhysicalDisk parameters in WinPE with Windows cumulative update
    $PDParam = @{}
    if ((Get-Command -Name 'Reset-PhysicalDisk').Parameters['Confirm']) {
        $PDParam.Add('Confirm',$false)
    }
    Get-PhysicalDisk | Reset-PhysicalDisk @PDParam

    Get-Disk | ? PartitionStyle -ne RAW | % {
        $_ | Set-Disk -IsOffline:$false -ErrorAction SilentlyContinue
        $_ | Set-Disk -IsReadOnly:$false -ErrorAction SilentlyContinue
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
    }

    Get-Disk | % {
        $_ | Set-Disk -IsReadOnly:$true -ErrorAction SilentlyContinue
        $_ | Set-Disk -IsOffline:$true -ErrorAction SilentlyContinue
    }

    Update-StorageProviderCache -DiscoveryLevel Full
    (Get-Date).ToString('yyyy/MM/dd HH:mm:ss') | Add-Content $logPath
    "Select the disk to boot from." | Add-Content $logPath
    Write-LogMessage -Message "Select the disk to boot from."

    Get-PhysicalDisk | Sort DeviceId | Format-Table DeviceId, Model, BusType, MediaType, Size | Out-String | Add-Content $logPath
    Get-Disk | Out-String | Add-Content $logPath

	$allbootCandidateDisks = Get-PhysicalDisk
	if (-not $allbootCandidateDisks) {
		throw 'No suitable boot candidate disks found.'
	}

    "All disks." | Add-Content $logPath
	$allbootCandidateDisks | Out-String | Add-Content $logPath
    $bootCandidateDisks = $allbootCandidateDisks | ? BusType -in 'SATA', 'SAS', 'RAID'

    $bootCandidateDisks = $bootCandidateDisks | ? DeviceId -in (Get-Disk).Number
    $bootCandidateDisks = $bootCandidateDisks | Sort-Object Size, DeviceId
    $bootCandidateDisk = $bootCandidateDisks | Select-Object -First 1
    $bootDiskNumber = $bootCandidateDisk.DeviceId

    "Disk $bootDiskNumber will be used for boot partition." | Add-Content $logPath
    Write-LogMessage -Message "Disk $bootDiskNumber will be used for boot partition."

    
    $firstDisk = $bootCandidateDisks | Select-Object -First 1
    $secondDisk = $bootCandidateDisks | Select-Object -First 1 -Skip 1

    if ($firstDisk.Size -eq $secondDisk.Size) 
    {
        $secondDiskNumber = $secondDisk.DeviceId
        $ssdDisks = Get-PhysicalDisk | ? BusType -in 'SATA', 'SAS', 'RAID', 'NVMe' | ? MediaType -eq SSD
        $nonOnboardSsdDisks = $ssdDisks | ? DeviceId -notin $firstDisk.DeviceId, $secondDisk.DeviceId

        if ($nonOnboardSsdDisks) 
        {
            # We create partition on the secondary on-board SSD drive only in case there are more SSD disks to use for storage pool later on.
            "Disk $secondDiskNumber is considered a secondary on-board drive and will be formatted as a second volume to prevent joining it to storage pool." | Add-Content $logPath
            $null = Initialize-Disk -Number $secondDiskNumber -ErrorAction SilentlyContinue
            $partition = New-Partition -DiskNumber $secondDiskNumber -UseMaximumSize
        }
    }

    ##############################################################################################


    wpeutil UpdateBootInfo | Add-Content $LogPath

    $peFirmwareType = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control).PEFirmwareType

    # Returns 0x1 if the PC is booted into BIOS mode, or 0x2 if the PC is booted in UEFI mode.
    $isLegacyBoot = $peFirmwareType -eq 1

    if ($isLegacyBoot) 
    {
        "Create new partitions for Legacy Boot."| Add-Content $LogPath
        Write-LogMessage -Message "Create new partitions for Legacy Boot."
        $null = Initialize-Disk -Number $bootDiskNumber -PartitionStyle MBR -ErrorAction SilentlyContinue
        $partition = New-Partition -DiskNumber $bootDiskNumber -UseMaximumSize -AssignDriveLetter -IsActive
        $systemDrive = $partition.DriveLetter + ':'
        $osVolume = Format-Volume -Partition $partition -FileSystem NTFS -Confirm:$false
    } 
    else 
    {
        "Create new partitions for EUFI."| Add-Content $LogPath
        Write-LogMessage -Message "Create new partitions for EUFI."
        $null = Initialize-Disk -Number $bootDiskNumber -ErrorAction SilentlyContinue
        $espPartition = New-Partition -DiskNumber $bootDiskNumber -Size 200MB -GptType "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"  # ESP
        $msrPartition = New-Partition -DiskNumber $bootDiskNumber -Size 128MB -GptType "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" # MSR
        $osPartition = New-Partition -DiskNumber $bootDiskNumber -UseMaximumSize -AssignDriveLetter -GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}" # OS
        $osVolume = Format-Volume -Partition $osPartition -FileSystem NTFS -Confirm:$false
        $espPartition | Add-PartitionAccessPath -AccessPath Q:
        $null = format Q: /fs:FAT32 /v:EFS /Y
        $systemDrive = $osPartition.DriveLetter + ':'
        Write-LogMessage -Message "Using $systemDrive"
    }

    return [string]$systemDrive
}

function Set-HostVHDBoot
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $BootVHDFilePath,

        [Parameter(Mandatory=$true)]
        [string]
        $UnattendFile,

        [Parameter(Mandatory=$true)]
        [string]
        $SystemDrive,

        [Parameter(Mandatory=$true)]
        [string]
        $LogPath
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    try
    {
        Write-LogMessage -Message "Mounting VHD '$BootVHDFilePath'."
        "Mounting VHD '$BootVHDFilePath'." | Add-Content $logPath
        $null = Mount-DiskImage -ImagePath $BootVHDFilePath
        $virtualDiskDriveLetter = Get-Disk | ? BusType -like 'File Backed Virtual' | Get-Partition | ? Size -gt 2Gb | % DriveLetter
        $bootDrive = $virtualDiskDriveLetter + ':\'
        Write-Host $bootDrive

        # workaround for issue where script cannot find drive
        $null = New-PSDrive -Name $virtualDiskDriveLetter -Root $bootDrive -PSProvider FileSystem

        "Use-WindowsUnattend file '$UnattendFile' for offline values." | Add-Content $logPath
        Write-LogMessage -Message "Use-WindowsUnattend file '$UnattendFile' for offline values."
        $null = Use-WindowsUnattend -Path $bootDrive -UnattendPath $UnattendFile

        $unattendDirectory = "$($bootDrive)Windows\Panther\Unattend"
        "Inject Unattend file '$UnattendFile' to '$unattendDirectory'." | Add-Content $logPath
        Write-LogMessage -Message "Inject Unattend file '$UnattendFile' to '$unattendDirectory'."
        $null = New-Item -Path $unattendDirectory -ItemType Directory -Force
        $null = Copy-Item -Path $UnattendFile -Destination "$unattendDirectory\unattend.xml"

        $peFirmwareType = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control).PEFirmwareType
        # Returns 0x1 if the PC is booted into BIOS mode, or 0x2 if the PC is booted in UEFI mode.
        $isLegacyBoot = $peFirmwareType -eq 1

        if ($isLegacyBoot) 
        {
            "Set BCD Boot Legacy." | Add-Content $logPath
            Write-LogMessage -Message "Set BCD Boot Legacy."
            bcdboot "$($bootDrive)Windows" /S $systemDrive | Add-Content $logPath
        } 
        else 
        {
            "Set BCD Boot UEFI." | Add-Content $logPath
            Write-LogMessage -Message "Set BCD Boot UEFI."
            bcdboot "$($bootDrive)Windows" /s Q: /f UEFI /d /addlast /v | Add-Content $logPath

            # Remove invalid Windows Boot Manager entries, left from the previous deployment.
            $bcdFirmware = bcdedit /enum firmware
            $bcdFirmware | Add-Content $logPath
            $bcdFirmware = $bcdFirmware -join "`n"
            if ($bcdFirmware -match 'identifier\s*({\w*-[0-9a-z-]*})[^-]*?description\s*Windows Boot Manager') 
            {
                for($i = 0; $i -lt $matches.Count; $i++) 
                {
                    if ($matches[$i] -like '{*') 
                    {
                        bcdedit /delete $matches[$i]
                    }
                }
            }

            bcdedit /enum firmware | Add-Content $logPath
        }
    }
    finally
    {
        $mountedImages = Get-DiskImage -ImagePath $BootVHDFilePath 
        if ($mountedImages) 
        {
            Write-LogMessage -Message "Dismount image $BootVHDFilePath"
            $null = Dismount-DiskImage -ImagePath $BootVHDFilePath
        }
    }
}

function Write-LogMessage 
{
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
        [string]$SystemName = "WIN-PE",
        [parameter(Mandatory = $false)]
        [string]$Message = ''
    )

  BEGIN {}
  PROCESS {
    Write-Verbose "Writing log message"
    # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
    write-host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline;
    write-host ' - [' -ForegroundColor White -NoNewline;
    write-host $systemName -ForegroundColor Yellow -NoNewline;
    write-Host "]::$($message)" -ForegroundColor White;
  }
  END {}
} 

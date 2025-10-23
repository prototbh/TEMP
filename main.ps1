<#
.SYNOPSIS
  HWID-Superdump.ps1 - comprehensive hardware & system identifier dump.

.DESCRIPTION
  Gathers disk serials, physical media, CPU ids, BIOS, baseboard, SMBIOS UUID,
  network adapter info (MACs, GUIDs), TPM info, Windows MachineGuid, OS install id,
  volumes, partitions, physical disks, SCSI info, USB devices, GPU info, user SID, etc.
  Outputs pretty console view and saves JSON + text logs into OutputDir.

.PARAMETER OutputDir
  Directory to save logs. Defaults to current directory's "HWID-Logs".

.PARAMETER MonitorInterval
  If > 0, script refreshes every MonitorInterval seconds. 0 (default) means run once.

.EXAMPLE
  .\HWID-Superdump.ps1 -OutputDir C:\HWID -MonitorInterval 0
#>

param(
    [string]$OutputDir = (Join-Path -Path (Get-Location) -ChildPath "HWID-Logs"),
    [int]$MonitorInterval = 0
)

function Ensure-Dir { param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null } }

function Get-RegistryValue([string]$key, [string]$value) {
    try {
        $v = Get-ItemProperty -Path $key -Name $value -ErrorAction Stop
        return $v.$value
    } catch { return $null }
}

function Collect-All {
    # Timestamp for this snapshot
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $isAdmin = (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

    # Basic system info
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue
    $physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
    $physicalMedia = Get-CimInstance -ClassName Win32_PhysicalMedia -ErrorAction SilentlyContinue
    $partitions = Get-CimInstance -ClassName Win32_DiskPartition -ErrorAction SilentlyContinue
    $volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction SilentlyContinue
    $netAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue
    $netConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue
    $gpu = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue
    $usb = Get-CimInstance -ClassName Win32_USBControllerDevice -ErrorAction SilentlyContinue
    $scsi = Get-CimInstance -ClassName Win32_SCSIController -ErrorAction SilentlyContinue
    $biosSettings = $bios | Select-Object SerialNumber, SMBIOSBIOSVersion, Manufacturer, ReleaseDate
    $machineGuid = Get-RegistryValue -key "HKLM:\SOFTWARE\Microsoft\Cryptography" -value "MachineGuid"
    $productId = Get-RegistryValue -key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -value "ProductId"
    $installDate = if ($os -and $os.InstallDate) { ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)) } else { $null }
    $user = [Environment]::UserName
    $domain = [Environment]::UserDomainName
    $userSid = try { (New-Object System.Security.Principal.NTAccount("$domain\$user")).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
    $whoami = (whoami /user 2>$null) -split "`n" | Select-Object -Last 1
    $tpm = $null
    try { $tpm = Get-Tpm -ErrorAction SilentlyContinue } catch { $tpm = $null }

    # Helper: match physical media to diskdrive
    $diskDetails = @()
    foreach ($d in $physicalDisks) {
        $matchingMedia = $physicalMedia | Where-Object {
            # Try multiple heuristics: Tag equals DeviceID or contains last part, or PNPDeviceID matches
            ($_.Tag -and $d.DeviceID -and $_.Tag -eq $d.DeviceID) -or
            ($_.Tag -and $d.DeviceID -and $_.Tag -like "*$($d.DeviceID.Split('\\')[-1])*") -or
            ($_.Tag -and $d.PNPDeviceID -and $_.Tag -like "*$($d.PNPDeviceID.Split('\\')[-1])*")
        } | Select-Object -First 1

        $serial = if ($matchingMedia -and $matchingMedia.SerialNumber) { $matchingMedia.SerialNumber.Trim() } elseif ($d.SerialNumber) { $d.SerialNumber.Trim() } else { "<not available>" }

        $diskDetails += [PSCustomObject]@{
            Model        = $d.Model
            DeviceID     = $d.DeviceID
            PNPDeviceID  = $d.PNPDeviceID
            InterfaceType = $d.InterfaceType
            MediaType    = $d.MediaType
            SizeBytes    = $d.Size
            SerialNumber = $serial
            Caption      = $d.Caption
        }
    }

    # Network adapter details (include MACs, AdapterType, GUIDs where present)
    $netDetails = @()
    foreach ($n in $netAdapters | Sort-Object -Property Name) {
        $cfg = $netConfigs | Where-Object { $_.Index -eq $n.Index } | Select-Object -First 1
        $netDetails += [PSCustomObject]@{
            Name           = $n.Name
            NetConnectionID = $n.NetConnectionID
            DeviceID       = $n.DeviceID
            PNPDeviceID    = $n.PNPDeviceID
            MACAddress     = $n.MACAddress
            AdapterType    = $n.AdapterType
            Manufacturer   = $n.Manufacturer
            GUID           = $n.GUID
            IPEnabled      = $cfg.IPEnabled
            IPAddresses    = if ($cfg -and $cfg.IPAddress) { $cfg.IPAddress -join ", " } else { $null }
            DHCPEnabled    = $cfg.DHCPEnabled
            DNSHostName    = $cfg.DNSHostName
            Status         = $n.Status
        }
    }

    # Volumes & partitions
    $volumeDetails = @()
    foreach ($v in $volumes) {
        $volumeDetails += [PSCustomObject]@{
            DeviceID    = $v.DeviceID
            DriveLetter = $v.DriveLetter
            Label       = $v.Label
            FileSystem  = $v.FileSystem
            Capacity    = $v.Capacity
            FreeSpace   = $v.FreeSpace
            SerialNumber = $v.SerialNumber
            BootVolume  = $v.BootVolume
            SystemVolume = $v.SystemVolume
        }
    }

    # GPU list
    $gpuDetails = $gpu | Select-Object Name, DriverVersion, AdapterRAM, PNPDeviceID

    # USB devices - expand to linked device info
    $usbDetails = @()
    foreach ($u in $usb) {
        $assoc = $u.Dependent -replace '"',''
        $usbDetails += $assoc
    }

    # Additional: disk physical (Storage module), PhysicalDisk objects (if available)
    $storagePhysical = @()
    try {
        $storagePhysical = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, SerialNumber, MediaType, Size
    } catch {}

    # WMI / SMBIOS IDs: try to get as many fields as available
    $wmiIDs = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Manufacturer = $computerSystem.Manufacturer
        Model        = $computerSystem.Model
        SystemType   = $computerSystem.SystemType
        TotalPhysicalMemory = $computerSystem.TotalPhysicalMemory
        BIOS_SerialNumber = $bios.SerialNumber
        BIOS_Version = $bios.SMBIOSBIOSVersion
        Baseboard_Product = $baseboard.Product
        Baseboard_SerialNumber = $baseboard.SerialNumber
        ProcessorId = $processor.ProcessorId
        Processor_Name = $processor.Name
        SMBIOS_UUID = $csp.UUID
        MachineGuid = $machineGuid
        WindowsProductId = $productId
        OS_Caption = $os.Caption
        OS_Build = $os.BuildNumber
        OS_InstallDate = $installDate
        IsAdministrator = $isAdmin
        User = "$domain\$user"
        UserSID = $userSid
    }

    # Compose final object
    $result = [PSCustomObject]@{
        SnapshotTime = $timestamp
        CollectedBy  = "HWID-Superdump.ps1"
        IsAdmin      = $isAdmin
        WMI_IDs      = $wmiIDs
        Disks        = $diskDetails
        PhysicalDisks_GetPhysicalDisk = $storagePhysical
        Partitions   = $partitions
        LogicalDisks = $logicalDisks
        Volumes      = $volumeDetails
        NetworkAdapters = $netDetails
        GPUs         = $gpuDetails
        USB_References = $usbDetails
        SCSI_Controllers = $scsi
        TPM          = $tpm
        WhoAmI       = $whoami
        Registry_MachineGuid = $machineGuid
        Registry_WindowsProductId = $productId
        OS           = $os
        ComputerSystem= $computerSystem
    }

    return $result
}

# --- Preparation
Ensure-Dir -d $OutputDir

# Main run / monitor loop
do {
    $snapshot = Collect-All
    $ts = $snapshot.SnapshotTime
    $jsonFile = Join-Path -Path $OutputDir -ChildPath ("HWID_{0}.json" -f $ts)
    $textFile = Join-Path -Path $OutputDir -ChildPath ("HWID_{0}.txt" -f $ts)

    # Save JSON
    try {
        $snapshot | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonFile -Encoding UTF8
    } catch {
        # fallback to manual serialization if depth problems
        $snapshot | Out-File -FilePath $jsonFile -Encoding UTF8
    }

    # Create a human-readable text summary
    $sb = New-Object System.Text.StringBuilder
    $sb.AppendLine(("HWID Superdump - {0}" -f (Get-Date))) | Out-Null
    $sb.AppendLine(("Computer: {0}" -f $snapshot.WMI_IDs.ComputerName)) | Out-Null
    $sb.AppendLine(("Model: {0}  Manufacturer: {1}" -f $snapshot.WMI_IDs.Model, $snapshot.WMI_IDs.Manufacturer)) | Out-Null
    $sb.AppendLine(("SMBIOS UUID: {0}" -f $snapshot.WMI_IDs.SMBIOS_UUID)) | Out-Null
    $sb.AppendLine(("MachineGuid (Registry): {0}" -f $snapshot.WMI_IDs.MachineGuid)) | Out-Null
    $sb.AppendLine(("Windows ProductId: {0}" -f $snapshot.WMI_IDs.WindowsProductId)) | Out-Null
    $sb.AppendLine(("ProcessorId: {0}" -f $snapshot.WMI_IDs.ProcessorId)) | Out-Null
    $sb.AppendLine(("BIOS Serial: {0}" -f $snapshot.WMI_IDs.BIOS_SerialNumber)) | Out-Null
    $sb.AppendLine(("Baseboard Serial: {0}" -f $snapshot.WMI_IDs.Baseboard_SerialNumber)) | Out-Null
    $sb.AppendLine("") | Out-Null

    $sb.AppendLine("=== Disks ===") | Out-Null
    foreach ($d in $snapshot.Disks) {
        $sb.AppendLine(("Model: {0} | DeviceID: {1} | Serial: {2} | Size: {3}" -f $d.Model, $d.DeviceID, $d.SerialNumber, ($d.SizeBytes))) | Out-Null
    }
    $sb.AppendLine("") | Out-Null

    $sb.AppendLine("=== Network Adapters ===") | Out-Null
    foreach ($n in $snapshot.NetworkAdapters) {
        $sb.AppendLine(("Name: {0} | MAC: {1} | GUID: {2} | IPs: {3} | Status: {4}" -f $n.Name, $n.MACAddress, $n.GUID, $n.IPAddresses, $n.Status)) | Out-Null
    }
    $sb.AppendLine("") | Out-Null

    $sb.AppendLine("=== Volumes ===") | Out-Null
    foreach ($v in $snapshot.Volumes) {
        $sb.AppendLine(("Device: {0} | Drive: {1} | Label: {2} | FS: {3} | Capacity: {4} | Free: {5}" -f $v.DeviceID, $v.DriveLetter, $v.Label, $v.FileSystem, $v.Capacity, $v.FreeSpace)) | Out-Null
    }

    $sb.AppendLine("") | Out-Null
    $sb.AppendLine("Full JSON saved to: $jsonFile") | Out-Null
    $sb.AppendLine("Full dump saved to: $textFile") | Out-Null

    # Write text file
    $sb.ToString() | Out-File -FilePath $textFile -Encoding UTF8

    # Print quick console summary (table-like)
    Clear-Host
    Write-Host "HWID Superdump - snapshot: $ts"
    Write-Host "Saved JSON -> $jsonFile"
    Write-Host "Saved Summary -> $textFile"
    Write-Host ""
    Write-Host "Computer: $($snapshot.WMI_IDs.ComputerName)  Model: $($snapshot.WMI_IDs.Model)  Manufacturer: $($snapshot.WMI_IDs.Manufacturer)"
    Write-Host "SMBIOS UUID: $($snapshot.WMI_IDs.SMBIOS_UUID)"
    Write-Host "MachineGuid (Registry): $($snapshot.WMI_IDs.MachineGuid)"
    Write-Host "ProcessorId: $($snapshot.WMI_IDs.ProcessorId)"
    Write-Host "BIOS Serial: $($snapshot.WMI_IDs.BIOS_SerialNumber)"
    Write-Host "Baseboard Serial: $($snapshot.WMI_IDs.Baseboard_SerialNumber)"
    Write-Host ""
    Write-Host "Top Disks:"
    $snapshot.Disks | Select-Object Model, SerialNumber, SizeBytes | Format-Table -AutoSize
    Write-Host ""
    Write-Host "Network Adapters (Name, MAC, GUID, Status):"
    $snapshot.NetworkAdapters | Select-Object Name, MACAddress, GUID, Status | Format-Table -AutoSize

    if ($MonitorInterval -gt 0) {
        Write-Host ""
        Write-Host "Monitoring: next refresh in $MonitorInterval seconds. Press Ctrl+C to stop."
        Start-Sleep -Seconds $MonitorInterval
    }

} while ($MonitorInterval -gt 0)

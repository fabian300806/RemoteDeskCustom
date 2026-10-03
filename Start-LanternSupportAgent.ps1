# Starts the Lantern agent from a user logon GPO script without blocking logon.

$ErrorActionPreference = 'Stop'
$agentPath = Join-Path $PSScriptRoot 'LanternSupportAgent.ps1'
$powerShellPath = Join-Path $PSHOME 'powershell.exe'
$userId = "$env:USERDOMAIN\$env:USERNAME"
$safeUserId = $userId -replace '[\\/:*?"<>|]', '_'
$taskName = "Lantern Support Agent - $safeUserId"

if (-not (Test-Path -LiteralPath $agentPath)) {
    throw "Lantern agent was not found at $agentPath"
}

$action = New-ScheduledTaskAction -Execute $powerShellPath -Argument "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

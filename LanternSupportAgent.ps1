# Lantern Support Agent
# Deploy through a GPO user logon script. The agent runs in the user's interactive session.
# Commands are written by an administrator to HKLM:\Software\Lantern\Support.

$ErrorActionPreference = 'Continue'
$statePath          = 'HKLM:\Software\Lantern\Support'
$statusPath         = 'HKCU:\Software\Lantern\Support'
$logPath            = Join-Path $env:LOCALAPPDATA 'Lantern\SupportAgent.log'
$sharedLogPath      = Join-Path $PSScriptRoot "SupportAgent-$env:COMPUTERNAME-$env:USERNAME.log"
$maximumLockSeconds = 1800
$mutex              = $null
$ownsMutex          = $false

New-Item -ItemType Directory -Path (Split-Path $logPath) -Force -ErrorAction SilentlyContinue | Out-Null

# ---------------------------------------------------------------------------
# Logging — thread-safe (usa mutex de archivo implícito de Add-Content)
# ---------------------------------------------------------------------------
function Write-Log([string]$message) {
    try {
        $maxLogBytes = 1MB
        if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt $maxLogBytes)) {
            $archive = "$logPath.1"
            Remove-Item $archive -Force -ErrorAction SilentlyContinue
            Move-Item $logPath $archive -Force -ErrorAction SilentlyContinue
        }
        $entry = "$(Get-Date -Format o) $message"
        Add-Content -Path $logPath -Value $entry -ErrorAction SilentlyContinue
        try { Add-Content -Path $sharedLogPath -Value $entry -ErrorAction Stop } catch {}
    } catch {}
}

# ---------------------------------------------------------------------------
# Ensamblados y P/Invoke
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;

// LanternInput — bloqueo de input mediante low-level hooks.
// WH_KEYBOARD_LL y WH_MOUSE_LL interceptan eventos ANTES de que lleguen
// a cualquier ventana, solo en la sesion interactiva del proceso que instala
// el hook. Las sesiones RDP entrantes tienen su propio canal de input
// (rdpinput) completamente independiente y NO son afectadas.
public static class LanternInput {

    private const int WH_KEYBOARD_LL = 13;
    private const int WH_MOUSE_LL    = 14;
    private const int HC_ACTION      = 0;

    private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    // Hooks activos
    private static IntPtr _kbHook  = IntPtr.Zero;
    private static IntPtr _msHook  = IntPtr.Zero;
    private static HookProc _kbProc; // GC pin
    private static HookProc _msProc; // GC pin
    private static Thread   _msgThread;
    private static volatile bool _blocking;

    private static IntPtr BlockAll(int nCode, IntPtr wParam, IntPtr lParam) {
        if (_blocking && nCode == HC_ACTION) return (IntPtr)1; // consumir evento
        return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
    }

    public static bool Install() {
        if (_kbHook != IntPtr.Zero) return true; // ya instalado
        _blocking = true;
        _kbProc   = BlockAll;
        _msProc   = BlockAll;

        // Los LL hooks necesitan un message loop en el mismo thread
        _msgThread = new Thread(() => {
            IntPtr hMod = GetModuleHandle(null);
            _kbHook = SetWindowsHookEx(WH_KEYBOARD_LL, _kbProc, hMod, 0);
            _msHook = SetWindowsHookEx(WH_MOUSE_LL,    _msProc, hMod, 0);

            // Bombear mensajes para que los hooks funcionen
            System.Windows.Forms.Application.Run();
        });
        _msgThread.SetApartmentState(ApartmentState.STA);
        _msgThread.IsBackground = true;
        _msgThread.Start();

        // Dar tiempo a que instale los hooks
        Thread.Sleep(300);
        return _kbHook != IntPtr.Zero;
    }

    public static void Uninstall() {
        _blocking = false;
        if (_kbHook != IntPtr.Zero) { UnhookWindowsHookEx(_kbHook); _kbHook = IntPtr.Zero; }
        if (_msHook != IntPtr.Zero) { UnhookWindowsHookEx(_msHook); _msHook = IntPtr.Zero; }
        if (_msgThread != null && _msgThread.IsAlive) {
            System.Windows.Forms.Application.ExitThread();
            _msgThread = null;
        }
    }
}
'@

# ---------------------------------------------------------------------------
# Registro: publicar estado
# ---------------------------------------------------------------------------
function Set-AgentStatus([string]$status, [string]$commandId = '', [string]$action = '') {
    try {
        New-Item -Path $statusPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $statusPath -Name AgentStatus       -Value $status                                                       -Force
        Set-ItemProperty -Path $statusPath -Name LastCommandId     -Value $commandId                                                    -Force
        Set-ItemProperty -Path $statusPath -Name LastAction        -Value $action                                                       -Force
        Set-ItemProperty -Path $statusPath -Name ProcessedAt       -Value (Get-Date).ToString('o')                                      -Force
        Set-ItemProperty -Path $statusPath -Name ComputerName      -Value $env:COMPUTERNAME                                            -Force
        Set-ItemProperty -Path $statusPath -Name Username          -Value "$env:USERDOMAIN\$env:USERNAME"                              -Force
        Set-ItemProperty -Path $statusPath -Name SessionId         -Value ([System.Diagnostics.Process]::GetCurrentProcess().SessionId) -Force
        if ($commandId) {
            Set-ItemProperty -Path $statusPath -Name LastSeenCommandId -Value $commandId -Force
        }
        Write-Log "Status=$status"
    } catch {
        Write-Log "StatusError=$($_.Exception.Message)"
    }
}

function Get-LastSeenCommandId {
    try { return [string](Get-ItemPropertyValue -Path $statusPath -Name LastSeenCommandId -ErrorAction Stop) }
    catch { return '' }
}

function Test-InteractiveSession {
    return [Environment]::UserInteractive -and
           ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -gt 0)
}

# ---------------------------------------------------------------------------
# Diálogo de consentimiento
# ---------------------------------------------------------------------------
function Show-LockPrompt {
    try {
        $dialog                 = New-Object System.Windows.Forms.Form
        $dialog.Text            = 'Lantern Support'
        $dialog.StartPosition   = 'CenterScreen'
        $dialog.Size            = New-Object System.Drawing.Size(460, 220)
        $dialog.TopMost         = $true
        $dialog.FormBorderStyle = 'FixedDialog'
        $dialog.MaximizeBox     = $false
        $dialog.MinimizeBox     = $false

        $message          = New-Object System.Windows.Forms.Label
        $message.Text     = "El equipo de soporte solicita iniciar una sesión de asistencia remota.`n`nDurante la asistencia se bloquearán temporalmente el teclado y el ratón.`nEl bloqueo se liberará automáticamente al finalizar."
        $message.Location = New-Object System.Drawing.Point(22, 20)
        $message.Size     = New-Object System.Drawing.Size(405, 90)
        $message.Font     = New-Object System.Drawing.Font('Segoe UI', 10)
        $dialog.Controls.Add($message)

        $accept              = New-Object System.Windows.Forms.Button
        $accept.Text         = 'Aceptar soporte'
        $accept.Location     = New-Object System.Drawing.Point(230, 130)
        $accept.Size         = New-Object System.Drawing.Size(150, 34)
        $accept.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $dialog.Controls.Add($accept)

        $cancel              = New-Object System.Windows.Forms.Button
        $cancel.Text         = 'Cancelar'
        $cancel.Location     = New-Object System.Drawing.Point(70, 130)
        $cancel.Size         = New-Object System.Drawing.Size(120, 34)
        $cancel.DialogResult = [System.Windows.Forms.DialogResult]::No
        $dialog.Controls.Add($cancel)

        $dialog.AcceptButton = $accept
        $dialog.CancelButton = $cancel
        $dialog.Add_Shown({ [LanternInput]::SetForegroundWindow($dialog.Handle) | Out-Null })

        $result = $dialog.ShowDialog()
        Write-Log "ConsentResult=$result"
        return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    } catch {
        Write-Log "LockPromptError=$($_.Exception.Message)"
        return $false
    } finally {
        if ($dialog) { try { $dialog.Dispose() } catch {} }
    }
}

# ---------------------------------------------------------------------------
# Toast de aviso (solo informativo, no intercepta nada)
# ---------------------------------------------------------------------------
function Show-Toast {
    try {
        # Instalar hooks de teclado y ratón — solo afectan la sesión local,
        # NO bloquean sesiones RDP entrantes.
        $hooked = [LanternInput]::Install()
        if (-not $hooked) {
            Write-Log "Hook install failed — input may not be fully blocked"
        } else {
            Write-Log "Hooks installed (keyboard+mouse blocked locally)"
        }
        $toast                 = New-Object System.Windows.Forms.Form
        $toast.FormBorderStyle = 'None'
        $toast.StartPosition   = 'Manual'
        $toast.Size            = New-Object System.Drawing.Size(360, 80)
        $toast.TopMost         = $true
        $toast.ShowInTaskbar   = $false
        $toast.BackColor       = [System.Drawing.Color]::FromArgb(20, 30, 48)
        $toast.Opacity         = 0.92

        $area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $toast.Location = New-Object System.Drawing.Point(
            ($area.Right  - $toast.Width  - 18),
            ($area.Bottom - $toast.Height - 18)
        )

        $label           = New-Object System.Windows.Forms.Label
        $label.Text      = "Soporte en curso`nTeclado y ratón bloqueados"
        $label.Font      = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
        $label.ForeColor = [System.Drawing.Color]::White
        $label.AutoSize  = $false
        $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $label.Dock      = [System.Windows.Forms.DockStyle]::Fill
        $label.BackColor = [System.Drawing.Color]::Transparent
        $toast.Controls.Add($label)

        $toast.Add_FormClosing({ param($s,$e); $e.Cancel = $true })
        $toast.Show()
        Write-Log "Toast shown"
        return $toast
    } catch {
        Write-Log "ToastError=$($_.Exception.Message)"
        return $null
    }
}

function Close-Toast([ref]$toastRef) {
    # Desinstalar hooks — libera el input local sin afectar RDP
    try { [LanternInput]::Uninstall() } catch {}
    Write-Log "Hooks uninstalled"
    if ($toastRef.Value) {
        try { $toastRef.Value.Add_FormClosing({ param($s,$e); $e.Cancel = $false }) } catch {}
        try { $toastRef.Value.Close(); $toastRef.Value.Dispose() } catch {}
        $toastRef.Value = $null
        Write-Log "Toast closed"
    }
}

# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------
try {
    $sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $mutex     = New-Object System.Threading.Mutex -ArgumentList $false, "Global\LanternSupportAgent-$sessionId"
    $ownsMutex = $mutex.WaitOne(0)
    if (-not $ownsMutex) {
        Write-Log "Agent already running in session $sessionId — exiting duplicate"
        return
    }
    if (-not (Test-InteractiveSession)) {
        Write-Log 'Agent stopped: no interactive user session.'
        return
    }

    # ------------------------------------------------------------------
    # Runspace de polling — hilo .NET independiente del message loop.
    # Corre aunque BlockInput esté activo porque es un thread separado.
    # Comunica con el hilo principal a través de una ConcurrentQueue.
    # ------------------------------------------------------------------
    Add-Type -TypeDefinition @'
using System.Collections.Concurrent;
public class LanternQueue {
    public static ConcurrentQueue<string> Commands = new ConcurrentQueue<string>();
}
'@

    $pollScript = {
        param($statePath, $statusPath, $logPath, $sharedLogPath, $lastSeenId, $maximumLockSeconds)

        function RegLog([string]$msg) {
            try { Add-Content -Path $logPath -Value "$(Get-Date -Format o) [poll] $msg" -EA SilentlyContinue } catch {}
        }

        $lastCommandId = $lastSeenId

        while ($true) {
            try {
                $state = Get-ItemProperty -Path $statePath -ErrorAction Stop
                $id     = [string]$state.CommandId
                $action = [string]$state.Action

                if ($id -and $id -ne $lastCommandId) {
                    $lastCommandId = $id
                    RegLog "Queuing Action=$action Id=$id"
                    # Encolar la acción para el hilo principal
                    [LanternQueue]::Commands.Enqueue("$action|$id")
                }
            } catch {}
            Start-Sleep -Milliseconds 400
        }
    }

    $lastCommandId = Get-LastSeenCommandId
    Write-Log "Agent started Computer=$env:COMPUTERNAME User=$env:USERDOMAIN\$env:USERNAME Session=$sessionId LastSeenCmd=$lastCommandId"
    Set-AgentStatus 'Ready'

    # Iniciar runspace de polling
    $rs   = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $ps   = [powershell]::Create()
    $ps.Runspace = $rs
    $ps.AddScript($pollScript).AddArgument($statePath).AddArgument($statusPath).AddArgument($logPath).AddArgument($sharedLogPath).AddArgument($lastCommandId).AddArgument($maximumLockSeconds) | Out-Null
    $handle = $ps.BeginInvoke()
    Write-Log "Poll runspace started"

    # ------------------------------------------------------------------
    # Bucle principal — solo gestiona UI y BlockInput
    # No usa Start-Sleep largo para no bloquear DoEvents
    # ------------------------------------------------------------------
    $lockedAt   = $null
    $toastForm  = $null
    $tickMs     = 200   # intervalo del bucle en ms

    while ($true) {

        # Leer comandos encolados por el runspace de polling
        $item = $null
        while ([LanternQueue]::Commands.TryDequeue([ref]$item)) {
            $parts    = $item -split '\|', 2
            $action   = $parts[0]
            $cmdId    = if ($parts.Count -gt 1) { $parts[1] } else { '' }

            Write-Log "MainLoop Action=$action Id=$cmdId"

            if ($action -eq 'RequestLock' -and -not $lockedAt) {
                Set-AgentStatus 'WaitingForConsent' $cmdId $action

                if (Show-LockPrompt) {
                        # Instalar hooks y mostrar toast
                        $toastForm = Show-Toast
                        $lockedAt  = Get-Date
                        Set-AgentStatus 'Locked' $cmdId $action
                } else {
                    Set-AgentStatus 'Declined' $cmdId $action
                }

            } elseif ($action -eq 'Unlock') {
                $lockedAt = $null
                Close-Toast ([ref]$toastForm)
                Set-AgentStatus 'Ready' $cmdId $action
            }
        }

        # Desbloqueo automático por tiempo
        if ($lockedAt -and ((Get-Date) - $lockedAt).TotalSeconds -ge $maximumLockSeconds) {
            Write-Log "AutoUnlock: max time reached"
            $lockedAt = $null
            Close-Toast ([ref]$toastForm)
            Set-AgentStatus 'AutoUnlocked'
        }

        # Mantener el toast visible y procesar mensajes de Windows
        try { [System.Windows.Forms.Application]::DoEvents() } catch {}
        [System.Threading.Thread]::Sleep($tickMs)
    }

} catch {
    Write-Log "FatalError=$($_.Exception.Message) Stack=$($_.ScriptStackTrace)"
    Set-AgentStatus 'Error'
} finally {
    # Garantizar que el input siempre quede libre al salir
    try { [LanternInput]::Uninstall() } catch {}
    if ($toastForm)  { try { $toastForm.Close(); $toastForm.Dispose() } catch {} }
    if ($ps)         { try { $ps.Stop(); $ps.Dispose() }               catch {} }
    if ($rs)         { try { $rs.Close(); $rs.Dispose() }              catch {} }
    if ($ownsMutex -and $mutex) {
        try { $mutex.ReleaseMutex() } catch {}
        try { $mutex.Dispose()      } catch {}
    }
}

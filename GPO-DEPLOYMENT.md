# Despliegue del agente Lantern mediante GPO

El agente debe ejecutarse en la sesión interactiva del usuario, no como tarea de `SYSTEM`, porque el bloqueo de entrada debe afectar al escritorio visible.

## 1. Copiar el agente y el lanzador

Copia `LanternSupportAgent.ps1` y `Start-LanternSupportAgent.ps1` a una ubicación de solo lectura para los usuarios del dominio, por ejemplo:

```text
\\DOMINIO\SYSVOL\DOMINIO\scripts\LanternSupportAgent.ps1
\\DOMINIO\SYSVOL\DOMINIO\scripts\Start-LanternSupportAgent.ps1
```

Concede lectura a `Authenticated Users` y modifica el script solo desde administración. No uses una ruta local del servidor; el script debe ejecutarse mediante una ruta UNC accesible desde cada equipo.

En `HKLM\Software\Lantern\Support`, limita la ACL para que solo `Administrators` o el grupo delegado de soporte pueda escribir. Los usuarios normales necesitan únicamente lectura; no deben poder modificar `Action` ni `CommandId`.

## 2. Crear la GPO

### Opción recomendada: Tarea programada mediante Preferencias de GPO

Para un agente residente, usa una tarea programada de usuario y no un script de logon que permanezca ejecutándose:

1. En Group Policy Management, abre `User Configuration > Preferences > Control Panel Settings > Scheduled Tasks`.
2. Crea una tarea `Scheduled Task (At least Windows 7)` con el nombre `Lantern Support Agent`.
3. En **Security options**, usa el usuario que ha iniciado sesión y selecciona **Run only when user is logged on**. No uses `SYSTEM`.
4. Añade un trigger **At log on** para cualquier usuario.
5. Configura la acción **Start a program**:

```text
Program: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Arguments: -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "\\10.35.10.1\scripts\LanternSupportAgent.ps1"
```

6. En **Settings**, habilita el reinicio de la tarea si falla y no establezcas un límite de tiempo para la ejecución.
7. Quita `LanternSupportAgent.ps1` de `User Configuration > Windows Settings > Scripts (Logon/Logoff)` si todavía aparece allí.
8. Ejecuta `gpupdate /force`, cierra sesión y vuelve a iniciarla.

Comprueba en el equipo cliente:

```powershell
Get-ScheduledTask -TaskName 'Lantern Support Agent'
Get-Content "$env:LOCALAPPDATA\Lantern\SupportAgent.log" -Tail 10
```

Debe aparecer `Agent started` con un `SessionId` mayor que cero y `Status=Ready`. Esta opción es preferible porque la GPO solo configura la tarea; el proceso residente no mantiene bloqueado el procesamiento del inicio de sesión.

### Opción alternativa: lanzador de logon

En Group Policy Management:

1. Crea o edita una GPO y vincúlala a la OU donde están las cuentas de usuario que reciben soporte.
2. Ve a `User Configuration > Windows Settings > Scripts (Logon/Logoff)`.
3. Configura **Logon**, no `Computer Configuration > Startup`: el agente necesita ejecutarse dentro de la sesión gráfica del usuario.
4. Añade como script de logon el lanzador, no el agente residente:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "\\DOMINIO\SYSVOL\DOMINIO\scripts\Start-LanternSupportAgent.ps1"
```

El lanzador registra o actualiza una tarea programada `Lantern Support Agent - DOMINIO_USUARIO` para el usuario actual y la inicia en su sesión interactiva. El nombre incluye el usuario para evitar colisiones cuando varias cuentas usan el mismo equipo. El lanzador termina inmediatamente; `LanternSupportAgent.ps1` conserva su bucle de monitorización dentro de la tarea y no bloquea `gpupdate` ni el inicio de sesión.

5. Ejecuta `gpupdate /force` y cierra/inicia sesión para probarlo.

Puedes verificarlo en cada equipo con:

```powershell
Get-Process powershell | Where-Object { $_.CommandLine -like '*LanternSupportAgent.ps1*' }
Get-ScheduledTask | Where-Object { $_.TaskName -like 'Lantern Support Agent -*' }
```

Para detener la tarea durante una prueba:

```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -like 'Lantern Support Agent -*' } | Stop-ScheduledTask
```

El diagnóstico del agente queda en:

```text
%LOCALAPPDATA%\Lantern\SupportAgent.log
```

Busca `BlockInput(True) succeeded`. Si aparece `BlockFailed`, revisa que el proceso esté en la sesión interactiva del usuario y no como `SYSTEM`. El estado `BlockFailed` también queda en `HKCU\Software\Lantern\Support`.

La consola escribe por cada orden `CommandId`, `RequestedBy`, `RequestedAt`, `ExpiresAt` y `Reason`. El agente publica `AgentStatus`, `LastCommandId`, `LastAction`, `ProcessedAt`, `ComputerName`, `Username` y `SessionId` en el perfil del usuario. Los estados principales son `Ready`, `WaitingForConsent`, `Locked`, `Declined`, `BlockFailed`, `AutoUnlocked` y `Error`.

Para una prueba inicial, crea una OU piloto, vincula allí la GPO y valida primero con uno o dos equipos.

## 3. Preparar PowerShell Remoting

En una GPO separada y limitada a la OU piloto, habilita WinRM y permite el acceso desde el equipo de soporte. La cuenta que ejecuta Lantern debe ser administrador local en los equipos administrados o tener delegación equivalente para escribir en `HKLM`.

Prueba desde el equipo de soporte antes de usar Lantern:

```powershell
Test-WSMan NOMBRE_EQUIPO
Invoke-Command -ComputerName NOMBRE_EQUIPO -ScriptBlock { hostname }
```

Si esas pruebas fallan, Lantern tampoco podrá enviar `RequestLock` o `Unlock`.

## 4. Permisos para enviar órdenes

La cuenta que ejecuta Lantern debe poder modificar remotamente:

```text
HKLM\Software\Lantern\Support
```

La aplicación envía las órdenes mediante PowerShell Remoting. Habilita WinRM únicamente en la OU necesaria y limita la delegación a las cuentas de soporte.

## Seguridad

- El usuario siempre ve y acepta el aviso antes del bloqueo.
- El bloqueo se libera con la acción `Unlock` desde Lantern.
- El agente tiene un desbloqueo automático de 30 minutos.
- Prueba primero en una OU piloto.
- No despliegues el script como `SYSTEM`; no interactuaría con el escritorio del usuario.

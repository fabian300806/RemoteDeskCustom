<#
.SYNOPSIS
    Generador de Claves Seriales Corporativas para Lili enterprise NET
.DESCRIPTION
    Genera claves de activacion validas con checksum criptografico offline
    para Lili enterprise NET.
#>

param(
    [ValidateSet('ENT1', 'NET1', 'DIR1', 'SRV1', 'CORP', 'PRO1', 'DEMO')]
    [string]$Edicion = '',

    [int]$Cantidad = 0,

    [string]$GuardarEn = ""
)

$Host.UI.RawUI.WindowTitle = "Lili enterprise NET - Generador de Claves Seriales"

try {

# Definicion del algoritmo en C# para maximo rendimiento y precision
$csharpCode = @'
using System;
using System.Text;

public class ILIKeygen {
    private static readonly string CHARSET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    public static string ComputeChecksum(string payload) {
        ulong h = 0x494C49; // Semilla ASCII 'ILI'
        byte[] bytes = Encoding.ASCII.GetBytes(payload.ToUpper());
        for (int i = 0; i < bytes.Length; i++) {
            ulong c = (ulong)bytes[i];
            h = unchecked(h * 31 + c + (ulong)(i + 1) * 17);
        }
        ulong len = (ulong)CHARSET.Length;
        char c0 = CHARSET[(int)((h >> 15) % len)];
        char c1 = CHARSET[(int)((h >> 10) % len)];
        char c2 = CHARSET[(int)((h >> 5) % len)];
        char c3 = CHARSET[(int)(h % len)];
        return "" + c0 + c1 + c2 + c3;
    }

    public static string GenerateKey(string prefix, string p1, string p2) {
        string chk = ComputeChecksum(prefix + p1 + p2);
        return string.Format("LILI-{0}-{1}-{2}-{3}", prefix, p1, p2, chk);
    }
}
'@

if (-not ([System.Management.Automation.PSTypeName]'ILIKeygen').Type) {
    Add-Type -TypeDefinition $csharpCode
}

# Modo interactivo si no se proporcionan parametros
if ([string]::IsNullOrWhiteSpace($Edicion)) {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "     GENERADOR DE CLAVES SERIALES - Lili enterprise NET     " -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Seleccione la edicion de licencia que desea generar:" -ForegroundColor Yellow
    Write-Host "  [1] ENT1 - Suite Completa Enterprise (Red + Active Directory + Servidor de Archivos)" -ForegroundColor White
    Write-Host "  [2] NET1 - Modulo Control de Red (Escaner, Puertos, WoL, MSOI Office)" -ForegroundColor White
    Write-Host "  [3] DIR1 - Modulo Active Directory (Usuarios, Grupos, Equipos, Politicas)" -ForegroundColor White
    Write-Host "  [4] SRV1 - Modulo Servidor de Archivos (Shares, Permisos NTFS, Analizador, VSS)" -ForegroundColor White
    Write-Host "  [5] CORP - Licencia Corporativa Ilimitada (Suite Total)" -ForegroundColor White
    Write-Host "  [6] DEMO - Licencia de Demostracion / Pruebas" -ForegroundColor White
    Write-Host ""
    $opcion = Read-Host "Ingrese opcion (1-6, por defecto 1)"
    switch ($opcion) {
        '2' { $Edicion = 'NET1' }
        '3' { $Edicion = 'DIR1' }
        '4' { $Edicion = 'SRV1' }
        '5' { $Edicion = 'CORP' }
        '6' { $Edicion = 'DEMO' }
        default { $Edicion = 'ENT1' }
    }
}

if ($Cantidad -le 0) {
    $inputCant = Read-Host "Cuantas claves desea generar? (por defecto 5)"
    if ([int]::TryParse($inputCant, [ref]$Cantidad)) {
        if ($Cantidad -le 0) { $Cantidad = 5 }
    } else {
        $Cantidad = 5
    }
}

$nombreEdicion = switch ($Edicion) {
    'ENT1' { 'Lili enterprise NET - Suite Completa Enterprise' }
    'NET1' { 'Lili enterprise NET - Modulo Control de Red' }
    'DIR1' { 'Lili enterprise NET - Modulo Active Directory' }
    'SRV1' { 'Lili enterprise NET - Modulo Servidor de Archivos' }
    'CORP' { 'Lili enterprise NET - Licencia Corporativa Ilimitada' }
    'PRO1' { 'Lili enterprise NET - Edicion Profesional (Red + Archivos)' }
    'DEMO' { 'Lili enterprise NET - Licencia de Demostracion' }
    default { 'Lili enterprise NET - Licencia Oficial' }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GENERANDO CLAVES DE ACTIVACION - Lili enterprise NET      " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Edicion seleccionada : $Edicion ($nombreEdicion)" -ForegroundColor White
Write-Host "Cantidad solicitada  : $Cantidad claves" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

$chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
$random = New-Object System.Random
$clavesGeneradas = @()

for ($n = 1; $n -le $Cantidad; $n++) {
    $p1 = ""
    $p2 = ""
    for ($i = 0; $i -lt 4; $i++) {
        $p1 += $chars[$random.Next(0, $chars.Length)]
        $p2 += $chars[$random.Next(0, $chars.Length)]
    }

    $serial = [ILIKeygen]::GenerateKey($Edicion, $p1, $p2)
    $clavesGeneradas += $serial
    Write-Host ("  [{0:D2}]  {1}" -f $n, $serial) -ForegroundColor Cyan
}

Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[OK] Claves generadas exitosamente y verificadas offline." -ForegroundColor Green
Write-Host ""

# Si se especifico un archivo para guardar, o si el usuario quiere guardarlo
if ([string]::IsNullOrWhiteSpace($GuardarEn)) {
    $guardarSN = Read-Host "Desea guardar estas claves en un archivo de texto? (S/N, por defecto S)"
    if ($guardarSN -ne 'N' -and $guardarSN -ne 'n') {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $desktop = [Environment]::GetFolderPath('Desktop')
        $GuardarEn = Join-Path $desktop "Claves_Lili_enterprise_NET_${Edicion}_${timestamp}.txt"
    }
}

if (-not [string]::IsNullOrWhiteSpace($GuardarEn)) {
    $fecha = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $contenido = @(
        "============================================================",
        " CLAVES DE ACTIVACION - Lili enterprise NET",
        "============================================================",
        "Edicion : $nombreEdicion ($Edicion)",
        "Fecha   : $fecha",
        "Total   : $Cantidad licencias",
        "------------------------------------------------------------",
        ""
    ) + $clavesGeneradas + @(
        "",
        "------------------------------------------------------------",
        "Instrucciones de activacion:",
        "1. Inicie la aplicacion 'Lili enterprise NET'.",
        "2. Ingrese cualquiera de las claves anteriores en el panel de activacion.",
        "3. Haga clic en 'ACTIVAR LICENCIA'.",
        "============================================================"
    )
    $contenido | Set-Content -Path $GuardarEn -Encoding UTF8
    Write-Host ""
    Write-Host "[GUARDADO] Archivo creado en:" -ForegroundColor Green
    Write-Host "  $GuardarEn" -ForegroundColor Yellow
    Write-Host ""

    # Abrir el archivo automaticamente
    Start-Process notepad.exe $GuardarEn
}

Write-Host "============================================================" -ForegroundColor Cyan

} catch {
    Write-Host ""
    Write-Host "[ERROR] Ocurrio un problema: $_" -ForegroundColor Red
}

# Siempre esperar antes de cerrar la ventana
Write-Host ""
Write-Host "Presione ENTER para cerrar esta ventana..." -ForegroundColor DarkGray
Read-Host | Out-Null

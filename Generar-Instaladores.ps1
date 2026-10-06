# ============================================================================
# Lili enterprise NET — Compilador y Generador Automático de Instaladores (.EXE y .MSI)
# ============================================================================
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
Set-Location $root

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   GENERADOR DE INSTALADORES — LILI ENTERPRISE NET          " -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Compilar binarios en modo Release
Write-Host "`n[1/3] Compilando binarios en modo Release..." -ForegroundColor Yellow
cargo build --release --bins

# 2. Generar Instalador .EXE (Inno Setup)
Write-Host "`n[2/3] Generando Instalador .EXE (Inno Setup)..." -ForegroundColor Yellow
$iscc = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) {
    $iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
}
if (-not (Test-Path $iscc)) {
    $iscc = "C:\Program Files\Inno Setup 6\ISCC.exe"
}

if (Test-Path $iscc) {
    & $iscc "installer\installer.iss"
    Write-Host "[OK] Instalador .EXE generado en 'dist/'" -ForegroundColor Green
} else {
    Write-Warning "ISCC.exe no encontrado. Instala Inno Setup 6 para generar el .exe."
}

# 3. Generar Instalador .MSI (WiX Toolset)
Write-Host "`n[3/3] Generando Paquete .MSI (WiX Toolset)..." -ForegroundColor Yellow
$wix = "$env:USERPROFILE\.dotnet\tools\wix.exe"
if (-not (Test-Path $wix)) {
    $wix = (Get-Command wix -ErrorAction SilentlyContinue).Source
}

if ($wix -and (Test-Path $wix)) {
    & $wix build -arch x64 "installer\package.wxs" -o "dist\Lili-Enterprise-NET-v0.1.9.msi"
    Write-Host "[OK] Instalador .MSI generado en 'dist/'" -ForegroundColor Green
} else {
    Write-Warning "WiX CLI no encontrado. Instala WiX con 'dotnet tool install -g wix --version 5.0.2'."
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Instaladores disponibles en la carpeta 'dist/':" -ForegroundColor White
Get-ChildItem -Path "dist" -Include *.exe,*.msi -File | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
Write-Host "============================================================`n" -ForegroundColor Cyan

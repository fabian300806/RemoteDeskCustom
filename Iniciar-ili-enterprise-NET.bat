@echo off
title ili enterprise NET
cd /d "%~dp0"

if exist "target\release\lantern_scan.exe" (
    start "" "target\release\lantern_scan.exe"
) else (
    echo [INFO] Binario release no encontrado. Iniciando con Cargo...
    cargo run --release
)

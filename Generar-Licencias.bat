@echo off
chcp 65001 >nul
title Lili enterprise NET - Generador de Claves Seriales
color 0b
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Generar-Licencias.ps1"

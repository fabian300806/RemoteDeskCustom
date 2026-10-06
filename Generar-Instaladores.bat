@echo off
chcp 65001 >nul
title Lili enterprise NET — Compilador de Instaladores
color 0b
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Generar-Instaladores.ps1"
pause

@echo off
REM run_tests_admin.bat
REM Automatically elevates to Administrator and runs tests
REM Double-click this file to run

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run_tests
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run_tests
title NIDS Test Suite - Administrator Mode
color 0A
cls

echo ╔═══════════════════════════════════════════════════╗
echo ║    NIDS Testing Suite - Administrator Mode        ║
echo ╚═══════════════════════════════════════════════════╝
echo.
echo ✓ Running with Administrator privileges
echo.

set /p target="Enter target IP (or press Enter for 127.0.0.1): "
if "%target%"=="" set target=127.0.0.1

echo.
echo Target: %target%
echo.
echo Available Tests:
echo 1. ICMP Flood (Ping Flood)
echo 2. TCP Port Scan
echo 3. SSH Brute Force
echo 4. UDP Flood
echo 5. Run All Tests
echo 6. Exit
echo.

set /p choice="Select test (1-6): "

if "%choice%"=="1" goto icmp_flood
if "%choice%"=="2" goto port_scan
if "%choice%"=="3" goto ssh_brute
if "%choice%"=="4" goto udp_flood
if "%choice%"=="5" goto all_tests
if "%choice%"=="6" goto end

:icmp_flood
echo.
echo ╔════════════════════════════════════╗
echo ║    ICMP Flood Test                ║
echo ╚════════════════════════════════════╝
echo Sending 60 rapid ping requests...
echo.

for /L %%i in (1,1,60) do (
    ping -n 1 -l 32 %target% >nul
    if %%i==10 echo Sent 10 pings...
    if %%i==20 echo Sent 20 pings...
    if %%i==30 echo Sent 30 pings...
    if %%i==40 echo Sent 40 pings...
    if %%i==50 echo Sent 50 pings...
    if %%i==60 echo Sent 60 pings...
)

echo.
echo ✓ ICMP Flood test completed!
echo Expected: ICMP flood alert in NIDS
goto end_test

:port_scan
echo.
echo ╔════════════════════════════════════╗
echo ║    TCP Port Scan Test             ║
echo ╚════════════════════════════════════╝
echo Scanning ports (requires nmap)...
echo.

where nmap >nul 2>&1
if %errorLevel%==0 (
    nmap -sS -p 1-100 %target%
) else (
    echo ERROR: nmap not found!
    echo Please install nmap from: https://nmap.org/download.html
    echo Or use PowerShell version of this script
)

echo.
echo ✓ Port scan test completed!
goto end_test

:ssh_brute
echo.
echo ╔════════════════════════════════════╗
echo ║  SSH Brute Force Simulation       ║
echo ╚════════════════════════════════════╝
echo Simulating 10 SSH connection attempts...
echo.

for /L %%i in (1,1,10) do (
    echo SSH attempt %%i/10...
    powershell -Command "Test-NetConnection -ComputerName %target% -Port 22 -WarningAction SilentlyContinue | Out-Null"
    timeout /t 1 /nobreak >nul
)

echo.
echo ✓ SSH brute force test completed!
goto end_test

:udp_flood
echo.
echo ╔════════════════════════════════════╗
echo ║         UDP Flood Test            ║
echo ╚════════════════════════════════════╝
echo Sending 250 UDP packets...
echo.

powershell -Command "$udp = New-Object System.Net.Sockets.UdpClient; $bytes = New-Object byte[] 1024; for ($i=1; $i -le 250; $i++) { try { $udp.Send($bytes, $bytes.Length, '%target%', 1234) | Out-Null; if ($i %% 50 -eq 0) { Write-Host \"Sent $i packets...\" } } catch {} }; $udp.Close()"

echo.
echo ✓ UDP flood test completed!
goto end_test

:all_tests
echo.
echo ╔════════════════════════════════════╗
echo ║      Running All Tests            ║
echo ╚════════════════════════════════════╝
echo.

call :icmp_flood
timeout /t 3 /nobreak >nul
call :ssh_brute
timeout /t 3 /nobreak >nul
call :udp_flood

echo.
echo ✓ All tests completed!
goto end_test

:end_test
echo.
echo ═══════════════════════════════════════════════════
echo Check your NIDS monitoring window for alerts!
echo ═══════════════════════════════════════════════════
echo.

:end
pause
exit
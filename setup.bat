@echo off
echo Setting up WhatsApp Clone Chat App...
echo.

echo Installing dependencies...
c:/python314/python.exe -m pip install --upgrade pip
c:/python314/python.exe -m pip install -r whatsapp-clone/requirements.txt
echo.

echo Starting the app...
start cmd /k "c:/python314/python.exe whatsapp-clone/app.py"

echo.
echo App is starting... Once loaded, your local IP will be shown below.
timeout /t 3 >nul
c:/python314/python.exe get_ip.py
pause

@echo off
echo Setting up WhatsApp Clone Chat App...
echo.

echo Installing dependencies...
c:/python314/python.exe -m pip install --upgrade pip
c:/python314/python.exe -m pip install Flask==2.3.3 Flask-SocketIO==5.3.6 python-socketio==5.8.0 Flask-SQLAlchemy==3.0.5 Flask-Login==0.6.3 pyinstaller==6.19.0
echo.

echo Starting the app...
start cmd /k "c:/python314/python.exe app.py"

echo.
echo App is starting... Once loaded, your local IP will be shown below.
timeout /t 3 >nul
c:/python314/python.exe get_ip.py

REM Run the server
python backend\server.py
pause

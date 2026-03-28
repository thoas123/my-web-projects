#!/bin/bash
echo "Setting up WhatsApp Clone Chat App..."
echo

echo "Installing dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install Flask==2.3.3 Flask-SocketIO==5.3.6 python-socketio==5.8.0 Flask-SQLAlchemy==3.0.5 Flask-Login==0.6.3 pyinstaller==6.19.0
echo

echo "Starting the app..."
python3 app.py
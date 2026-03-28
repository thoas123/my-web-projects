#!/bin/bash
echo "Setting up WhatsApp Clone Chat App..."
echo

echo "Installing dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
echo

echo "Starting the app..."
python3 app.py
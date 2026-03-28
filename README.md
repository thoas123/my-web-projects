# WhatsApp Clone

A simple real-time chat application built with Flask and SocketIO.

## Quick Start

### Windows
Double-click `setup.bat` or run:
```
setup.bat
```

### Linux/Mac
Run:
```
chmod +x setup.sh
./setup.sh
```

This will install dependencies and start the app at http://127.0.0.1:5000

## Accessing from Different Networks

The app now binds to all network interfaces. To chat across different networks:

### Local Network Access
1. Find your computer's local IP: Run `ipconfig` (Windows) or `ifconfig` (Linux/Mac) and look for IPv4 address (e.g., 192.168.1.100)
2. Share this IP with friends: `http://YOUR_LOCAL_IP:5000`
3. They can access from any device on the same WiFi network

### Internet Access (Global)
For friends in different cities/countries:

1. **Get your public IP**: Run `python get_public_ip.py` or visit whatismyip.com
2. **Port forwarding setup**:
   - Access your router admin (usually 192.168.1.1)
   - Find "Port Forwarding" or "NAT" settings
   - Forward external port 5000 to your local IP (e.g., 10.5.50.253) on port 5000
3. **Share the URL**: `http://YOUR_PUBLIC_IP:5000`

**⚠️ Important Security Notes**:
- This exposes your home network to the internet
- Anyone with the URL can access your app
- Consider adding user authentication
- Use HTTPS in production (Flask development server is HTTP only)
- Your ISP might block port 5000; try alternative ports if needed

### Cloud Deployment (Recommended for Global Access)
For reliable global access, deploy to a cloud service:

- **Railway** (Easiest, Free tier): `railway.app`
- **Render** (Free tier): `render.com`
- **Heroku** (Free dynos): `heroku.com`
- **AWS/Google Cloud**: Professional hosting

## 🚀 Railway Deployment Steps (Recommended)

### 1. Setup
```bash
# Install Railway CLI
npm install -g @railway/cli
# Or download from https://railway.app/cli

# Login
railway login
```

### 2. Deploy
```bash
# Initialize git repo (if not already)
git init
git add .
git commit -m "Initial commit"

# Create Railway project
railway init

# Deploy
railway up
```

### 3. Get URL
Railway will provide a URL like `https://your-project.railway.app`

### 4. Environment Variables (Optional)
```bash
# Set debug mode off
railway variables set FLASK_DEBUG=false
```

## 🟣 Heroku Deployment Steps

### 1. Setup
```bash
# Install Heroku CLI
# Download from https://devcenter.heroku.com/articles/heroku-cli

# Login
heroku login
```

### 2. Deploy
```bash
# Create Heroku app
heroku create your-chat-app-name

# Set Python buildpack
heroku buildpacks:set heroku/python

# Deploy
git push heroku main
```

### 3. Open App
```bash
heroku open
```

## 🔵 Render Deployment Steps

1. Sign up at render.com
2. Connect your GitHub repo
3. Choose "Web Service" → Python
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `python app.py`
6. Deploy

## 📋 Pre-Deployment Checklist

- [ ] `Procfile` exists with `web: python app.py`
- [ ] `runtime.txt` specifies Python version (e.g., `python-3.9.18`)
- [ ] `requirements.txt` is up to date
- [ ] App uses `os.getenv('PORT')` for dynamic port
- [ ] Debug mode disabled in production
- [ ] Static files served correctly
- [ ] No hardcoded localhost URLs

## 🔒 Security for Production

- Add user authentication
- Use HTTPS (cloud providers provide this)
- Set strong secret key: `os.getenv('SECRET_KEY')`
- Consider rate limiting
- Add input validation

### Mobile Access
- On mobile: Use the local or public IP instead of 127.0.0.1
- Install as PWA for app-like experience

## Features

- Real-time messaging
- User login with username
- Global chat room
- Active user list
- Message history
- System notifications
- Mobile responsive design
- PWA support (installable on mobile)

## Manual Installation

1. Install dependencies:
   pip install -r whatsapp-clone/requirements.txt

2. Run as web app:
   python whatsapp-clone/app.py

3. Open http://localhost:5000 in your browser.

## Run as desktop app

### Option 1 (easy, fallback): webview or browser
1. Install requirements:
   python -m pip install -r whatsapp-clone/requirements.txt
2. Run:
   python whatsapp-clone/desktop.py

If `pywebview` starts correctly, a native window appears. Otherwise, it opens your default browser.

### Option 2 (cross-platform GUI via PySide6)

1. Ensure requirements installed (`PySide6` included).
2. Run:
   python whatsapp-clone/desktop_pyside.py

### Option 3 (pack as one-file executable with PyInstaller)

1. Install pyinstaller if needed:
   python -m pip install pyinstaller
2. Build:
   pyinstaller --onefile whatsapp-clone/desktop.py
3. Run the generated EXE from `dist\desktop.exe`.

### Option 4 (web mode, most stable across all platforms)

1. Run:
   python whatsapp-clone/app.py
2. Open: http://127.0.0.1:5000

### Notes

- If `pywebview` fails on Windows due to `pythonnet` build issues (common on Python 3.14), use `desktop_pyside.py` or the browser mode.
- For advanced native packaging you can use Electron/Tauri by pointing them to `http://127.0.0.1:5000`.

## Usage

- Enter a username to join the chat.
- Type messages and press Enter or click Send.
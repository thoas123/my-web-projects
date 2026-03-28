import threading
import webbrowser
from app import app, socketio


def run_flask():
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)


def open_browser(url):
    webbrowser.open(url)


if __name__ == '__main__':
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    url = 'http://127.0.0.1:5000'
    try:
        import webview
        webview.create_window('WhatsApp Clone', url, width=900, height=700)
        webview.start()
    except Exception as e:
        print('`pywebview` is not available or failed; opening browser instead. Error:', e)
        open_browser(url)
        print('If you want a true desktop window, install pywebview+PySide6 or run desktop_pyside.py')
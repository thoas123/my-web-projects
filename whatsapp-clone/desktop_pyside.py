import threading
import sys
from app import app, socketio


def run_flask():
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)


if __name__ == '__main__':
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    from PySide6.QtWidgets import QApplication
    from PySide6.QtWebEngineWidgets import QWebEngineView

    app_qt = QApplication(sys.argv)
    view = QWebEngineView()
    view.setUrl('http://127.0.0.1:5000')
    view.setWindowTitle('WhatsApp Clone (PySide6)')
    view.resize(900, 700)
    view.show()

    sys.exit(app_qt.exec())
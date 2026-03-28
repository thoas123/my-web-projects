from datetime import datetime, timezone
import os

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me-in-production')
socketio = SocketIO(app)

rooms = {'global': set()}
messages = {'global': []}
user_sessions = {}  # sid -> (username, room)
MAX_HISTORY = 200

def add_message(room, msg):
    """Helper to store message and maintain history limit."""
    room_msgs = messages.setdefault(room, [])
    room_msgs.append(msg)
    if len(room_msgs) > MAX_HISTORY:
        room_msgs.pop(0)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join')
def on_join(data):
    username = data.get('username')
    room = data.get('room', 'global')
    if not username:
        return

    join_room(room)
    rooms.setdefault(room, set()).add(username)
    user_sessions[request.sid] = (username, room)

    # send users list to room
    emit('user_list', sorted(list(rooms[room])), room=room)

    # send history to newly joined user
    emit('history', messages.get(room, []))

    # announce
    system_msg = {
        'user': 'System',
        'text': f'{username} joined the chat.',
        'time': datetime.now(timezone.utc).strftime('%H:%M:%S')
    }
    add_message(room, system_msg)
    emit('message', system_msg, room=room)

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    if sid not in user_sessions:
        return

    username, room = user_sessions[sid]
    text = data.get('text', '') if isinstance(data, dict) else data

    if not text.strip():
        return

    msg = {
        'user': username,
        'text': text,
        'time': datetime.now(timezone.utc).strftime('%H:%M:%S')
    }

    add_message(room, msg)
    emit('message', msg, room=room)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    if sid not in user_sessions:
        return

    username, room = user_sessions.pop(sid)
    if room in rooms and username in rooms[room]:
        rooms[room].remove(username)

    emit('user_list', sorted(list(rooms.get(room, []))), room=room)
    leave_room(room)

    system_msg = {
        'user': 'System',
        'text': f'{username} left the chat.',
        'time': datetime.now(timezone.utc).strftime('%H:%M:%S')
    }
    add_message(room, system_msg)
    emit('message', system_msg, room=room)

if __name__ == '__main__':
    # Use environment variable for debug mode
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    socketio.run(app, host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=debug_mode)
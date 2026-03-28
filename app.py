from datetime import datetime
import os

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)

rooms = {'global': set()}
messages = {'global': []}
user_sessions = {}  # sid -> (username, room)
max_history = 200

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
        'time': datetime.utcnow().strftime('%H:%M:%S')
    }
    messages.setdefault(room, []).append(system_msg)
    if len(messages[room]) > max_history:
        messages[room].pop(0)
    emit('message', system_msg, room=room)

@socketio.on('message')
def handle_message(data):
    if isinstance(data, str):
        # Keep compatibility with simple strings
        user = 'Unknown'
        text = data
        room = 'global'
    else:
        user = data.get('user', 'Unknown')
        text = data.get('text', '')
        room = data.get('room', 'global')

    if not text.strip():
        return

    msg = {
        'user': user,
        'text': text,
        'time': datetime.utcnow().strftime('%H:%M:%S')
    }

    messages.setdefault(room, []).append(msg)
    if len(messages[room]) > max_history:
        messages[room].pop(0)

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
        'time': datetime.utcnow().strftime('%H:%M:%S')
    }
    messages.setdefault(room, []).append(system_msg)
    if len(messages[room]) > max_history:
        messages[room].pop(0)
    emit('message', system_msg, room=room)

if __name__ == '__main__':
    # Use environment variable for debug mode
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    socketio.run(app, host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=debug_mode)
var socket = io();
var username = '';

function login() {
    username = document.getElementById('username').value.trim();
    if (username) {
        document.getElementById('login').style.display = 'none';
        document.getElementById('chat').style.display = 'flex';
        socket.emit('join', {username: username, room: 'global'});
    }
}

function renderMessage(item) {
    var messages = document.getElementById('messages');
    var messageEl = document.createElement('div');
    messageEl.className = 'message';
    messageEl.innerHTML = '<strong>' + item.user + '</strong> <span class="time">[' + item.time + ']</span>: ' + item.text;
    messages.appendChild(messageEl);
    messages.scrollTop = messages.scrollHeight;
}

socket.on('history', function(history) {
    var messages = document.getElementById('messages');
    messages.innerHTML = '';
    history.forEach(function(item) {
        renderMessage(item);
    });
});

socket.on('message', function(item) {
    renderMessage(item);
});

socket.on('user_list', function(users) {
    var userList = document.getElementById('userList');
    userList.innerHTML = '<h3>Active Users</h3>';
    users.forEach(function(user) {
        var el = document.createElement('div');
        el.className = 'user-item';
        el.textContent = user;
        userList.appendChild(el);
    });
});

function sendMessage() {
    var msg = document.getElementById('message').value.trim();
    if (msg) {
        socket.emit('message', {user: username, text: msg, room: 'global'});
        document.getElementById('message').value = '';
    }
}

var messageInput = document.getElementById('message');
messageInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// Toggle user list on mobile
document.getElementById('toggleUsers').addEventListener('click', function() {
    var userList = document.getElementById('userList');
    if (userList.style.display === 'none' || userList.style.display === '') {
        userList.style.display = 'block';
    } else {
        userList.style.display = 'none';
    }
});
import { API_BASE_URL } from './config.js';

function extractToken(rawToken) {
  if (!rawToken) return null;
  const parts = rawToken.split(' ');
  return parts.length > 1 ? parts[1] : parts[0];
}

function handleOAuthRedirect() {
  if (!window.location.hash) return;
  const params = new URLSearchParams(window.location.hash.slice(1));
  const token = extractToken(params.get('token'));
  const role = params.get('role');

  if (!token) return;

  localStorage.setItem("token", token);
  if (role) localStorage.setItem("role", role);
  window.location.hash = '';

  const destination = role === 'admin' ? 'admin.html' : 'index.html';
  window.location.href = destination;
}

async function handleLogin(event) {
  event.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const messageElement = document.getElementById("message");
  const loadingElement = document.getElementById("loading");
  const submitButton = event.target.querySelector('button[type="submit"]');

  try {
    loadingElement.style.display = 'block';
    submitButton.disabled = true;

    const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (res.ok) {
      // Store only the raw token, without the "Bearer " prefix.
      const token = extractToken(data.token);
      if (token) localStorage.setItem("token", token);
      localStorage.setItem("role", data.role);

      window.location.href = "index.html";
    } else {
      messageElement.textContent = data.message;
    }
  } catch (error) {
    console.error("Login fetch error:", error);
    messageElement.textContent = "An error occurred. Could not connect to the server.";
  } finally {
    loadingElement.style.display = 'none';
    submitButton.disabled = false;
  }
}

async function handleRegister(event) {
  event.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirm-password").value;
  const messageElement = document.getElementById("message");

  // Client-side validation for matching passwords
  if (password !== confirmPassword) {
    messageElement.textContent = "Passwords do not match.";
    messageElement.className = "message error";
    return;
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (res.ok) {
      messageElement.textContent = "Registered successfully! Redirecting to login...";
      messageElement.className = "message success";
      setTimeout(() => window.location.href = "login.html", 1500);
    } else {
      messageElement.textContent = data.message;
      messageElement.className = "message error";
    }
  } catch (error) {
    console.error("Registration fetch error:", error);
    messageElement.textContent = "An error occurred. Could not connect to the server.";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  handleOAuthRedirect();
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);
  if (registerForm) registerForm.addEventListener("submit", handleRegister);

  // Attach logout listener if the button exists
  const logoutButton = document.getElementById("logout-button");
  if (logoutButton) {
    logoutButton.addEventListener("click", logout);
  }

  updateNav();
});

export function updateNav() {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");

  const myInquiriesLink = document.querySelector('nav a[href="my-inquiries.html"]');
  const adminLink = document.querySelector('nav a[href="admin.html"]');
  const loginLink = document.querySelector('nav a[href="login.html"]');
  const registerLink = document.querySelector('nav a[href="register.html"]');
  const logoutButton = document.getElementById("logout-button");

  if (token) {
    if (myInquiriesLink) myInquiriesLink.style.display = role === "user" ? "inline" : "none";
    if (adminLink) adminLink.style.display = role === "admin" ? "inline" : "none";
    if (loginLink) loginLink.style.display = "none";
    if (registerLink) registerLink.style.display = "none";
    if (logoutButton) logoutButton.style.display = "inline";
  } else {
    if (myInquiriesLink) myInquiriesLink.style.display = "none";
    if (adminLink) adminLink.style.display = "none";
    if (loginLink) loginLink.style.display = "inline";
    if (registerLink) registerLink.style.display = "inline";
    if (logoutButton) logoutButton.style.display = "none";
  }
}

export function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("role");
  window.location.href = "login.html";
}

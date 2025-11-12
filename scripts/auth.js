document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const messageElement = document.getElementById("message");

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;

      try {
        const response = await fetch("http://localhost:3000/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (response.ok) {
          localStorage.setItem("token", data.token);
          localStorage.setItem("role", data.role);
          window.location.href = "index.html"; // Redirect to home on success
        } else {
          messageElement.textContent = data.message || "Login failed.";
          messageElement.className = "message error";
        }
      } catch (error) {
        console.error("Login error:", error);
        messageElement.textContent = "An error occurred. Please try again.";
        messageElement.className = "message error";
      }
    });
  }

  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;

      try {
        const response = await fetch("http://localhost:3000/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (response.ok) {
          messageElement.textContent = "Registration successful! You can now log in.";
          messageElement.className = "message success";
          setTimeout(() => {
            window.location.href = "login.html";
          }, 2000);
        } else {
          messageElement.textContent = data.message || "Registration failed.";
          messageElement.className = "message error";
        }
      } catch (error) {
        console.error("Registration error:", error);
        messageElement.textContent = "An error occurred. Please try again.";
        messageElement.className = "message error";
      }
    });
  }

  // Always update the navigation bar on every page load to reflect the current auth state.
  updateNav();
});

function updateNav() {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");

  const myInquiriesLink = document.querySelector('nav a[href="my-inquiries.html"]');
  const myOrdersLink = document.querySelector('nav a[href="orders.html"]');
  const adminLink = document.querySelector('nav a[href="admin.html"]');
  
  const nav = document.querySelector('nav');
  let logoutButton = document.getElementById('logout-button'); // Give the logout button an ID
  let loginLink = document.querySelector('nav a[href="login.html"]');
  let registerLink = document.querySelector('nav a[href="register.html"]');
  
  if (token) {
    // User is logged in
    if (myInquiriesLink) myInquiriesLink.style.display = "inline";
    if (myOrdersLink) myOrdersLink.style.display = "inline";
    if (adminLink) adminLink.style.display = role === "admin" ? "inline" : "none";
    if (loginLink) loginLink.style.display = "none"; // Hide login link
    if (registerLink) registerLink.style.display = "none"; // Hide register link

    // Add logout button if it doesn't exist
    if (!logoutButton) {
      logoutButton = document.createElement('a');
      logoutButton.id = 'logout-button'; // Assign an ID
      logoutButton.href = "#";
      logoutButton.textContent = "Logout";
      logoutButton.onclick = logout;
      if (nav) nav.appendChild(logoutButton);
    }

  } else {
    // User is not logged in
    if (myInquiriesLink) myInquiriesLink.style.display = "none";
    if (myOrdersLink) myOrdersLink.style.display = "none";
    if (adminLink) adminLink.style.display = "none";

    // Add login and register links if they don't exist
    if (!loginLink) {
      loginLink = document.createElement('a');
      loginLink.href = 'login.html';
      loginLink.textContent = 'Login';
      if (nav) nav.appendChild(loginLink);
    }
    if (!registerLink) {
      registerLink = document.createElement('a');
      registerLink.href = 'register.html';
      registerLink.textContent = 'Register';
      if (nav) nav.appendChild(registerLink);
    }
    if (logoutButton) logoutButton.remove(); // Remove logout button if present
  }
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("role");
  window.location.href = "login.html";
}
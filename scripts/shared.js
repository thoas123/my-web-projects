import { updateNav, logout } from './auth.js';

document.addEventListener("DOMContentLoaded", () => {
  const navContainer = document.createElement("nav");
  navContainer.innerHTML = `
      <a href="index.html">Home</a>
      <a href="vehicles.html">Vehicles</a>
      <a href="about.html">About</a>
      <a href="contact.html">Contact</a>
      <a href="my-inquiries.html" style="display: none;">My Inquiries</a>
      <a href="admin.html" style="display: none;">Admin</a>
      <a href="login.html" style="display: none;">Login</a>
      <a href="register.html" style="display: none;">Register</a>
      <a href="#" id="logout-button" style="display: none;">Logout</a>
  `;

  // Add the nav to the top of the body
  document.body.prepend(navContainer);

  // Call updateNav to set the correct visibility of links
  updateNav();

  // Highlight the active navigation link
  let currentPage = window.location.pathname.split('/').pop();
  if (currentPage === '') {
    currentPage = 'index.html'; // Default to index.html for the root path
  }
  
    const activeLink = navContainer.querySelector(`a[href="${currentPage}"]`);
    if (activeLink) {
      activeLink.classList.add('active');
    }

  // Attach logout listener
  document.getElementById('logout-button').addEventListener('click', logout);
});
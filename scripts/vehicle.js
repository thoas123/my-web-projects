document.addEventListener("DOMContentLoaded", () => {
  const searchBar = document.getElementById("search-bar");
  if (searchBar) {
    searchBar.addEventListener("keyup", handleSearch);
  }
});
function handleSearch() {
  const searchTerm = document.getElementById("search-bar").value.toLowerCase();
  const vehicleCards = document.querySelectorAll(".car-card");
  vehicleCards.forEach((card) => {
    // Get the text content from the card's details
    const cardText = card.querySelector(".car-details").textContent.toLowerCase();
    // If the card's text includes the search term, show it; otherwise, hide it
    if (cardText.includes(searchTerm)) {
      card.style.display = "block";
    } else {
      card.style.display = "none";
    }
  });
}

async function saveInquiry(event, name, img, priceString) {
  event.preventDefault(); // Prevent the link from navigating

  const token = localStorage.getItem("token");
  if (!token) {
    alert("You must be logged in to make an inquiry.");
    window.location.href = "login.html";
    return;
  }

  // Clean and parse the price string (e.g., "$45,000" -> 45000)
  const price = parseFloat(priceString.replace(/[^0-9.-]+/g, ""));

  const inquiryData = {
    name,
    img,
    price,
    date: new Date().toISOString().split("T")[0], // Get YYYY-MM-DD format
    status: "Pending", // Default status for a new inquiry
  };

  try {
    const response = await fetch("http://localhost:3000/api/inquiries", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(inquiryData),
    });

    if (response.ok) {
      alert("Inquiry submitted successfully!");
      window.location.href = "my-inquiries.html";
    } else {
      const errorData = await response.json();
      alert(errorData.message || "Failed to submit inquiry. Please try again.");
    }
  } catch (error) {
    console.error("Error submitting inquiry:", error);
    alert("An error occurred while submitting your inquiry.");
  }
}
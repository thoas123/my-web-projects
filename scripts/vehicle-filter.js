export function filterVehicles() {
  const searchInput = document.getElementById("search-input");
  const typeFilter = document.getElementById("type-filter");
  const minPriceInput = document.getElementById("min-price");
  const maxPriceInput = document.getElementById("max-price");
  const resetButton = document.getElementById("reset-btn");
  const vehicleCards = document.querySelectorAll(".car-card");

  const applyFilters = () => {
    const searchTerm = searchInput.value.toLowerCase();
    const selectedType = typeFilter.value;
    const minPrice = parseFloat(minPriceInput.value) || 0;
    const maxPrice = parseFloat(maxPriceInput.value) || Infinity;

    vehicleCards.forEach((card) => {
      const name = card.querySelector("h3").textContent.toLowerCase();
      const type = card.dataset.type;
      const price = parseFloat(card.dataset.price);

      const matchesSearch = name.includes(searchTerm);
      const matchesType = !selectedType || type === selectedType;
      const matchesPrice = price >= minPrice && price <= maxPrice;

      if (matchesSearch && matchesType && matchesPrice) {
        card.style.display = "block";
      } else {
        card.style.display = "none";
      }
    });
  };

  const resetFilters = () => {
    searchInput.value = "";
    typeFilter.value = "";
    minPriceInput.value = "";
    maxPriceInput.value = "";
    applyFilters();
  };

  // Event Listeners
  searchInput.addEventListener("input", applyFilters);
  typeFilter.addEventListener("change", applyFilters);
  minPriceInput.addEventListener("input", applyFilters);
  maxPriceInput.addEventListener("input", applyFilters);
  resetButton.addEventListener("click", resetFilters);

  // Initial filter application
  applyFilters();
}
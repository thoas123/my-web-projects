document.addEventListener("DOMContentLoaded", () => {
  const gallery = document.querySelector(".featured-gallery");
  const carouselContainer = document.querySelector(".carousel-container");
  const prevBtn = document.querySelector(".prev-btn");
  const nextBtn = document.querySelector(".next-btn");

  if (!gallery || !carouselContainer || !prevBtn || !nextBtn) {
    // If elements are not on the page, do nothing.
    return;
  }

  const cards = document.querySelectorAll(".featured-card");
  let currentIndex = 0;
  let autoScrollInterval;

  // --- Carousel Logic ---
  
  function updateCarousel() {
    const cardWidth = cards[0].offsetWidth;
    const gap = 20; // The gap between cards
    const moveDistance = (cardWidth + gap) * currentIndex;
    gallery.style.transform = `translateX(-${moveDistance}px)`;
  }

  function moveToNext() {
    if (currentIndex < cards.length - 1) {
      currentIndex++;
    } else {
      currentIndex = 0; // Loop back to the start
    }
    updateCarousel();
  }

  function moveToPrev() {
    if (currentIndex > 0) {
      currentIndex--;
    } else {
      currentIndex = cards.length - 1; // Loop to the end
    }
    updateCarousel();
  }

  // --- Auto-scroll Logic ---

  function startAutoScroll() {
    autoScrollInterval = setInterval(moveToNext, 3000); // Auto-scroll every 3 seconds
  }

  function stopAutoScroll() {
    clearInterval(autoScrollInterval);
  }

  // --- Event Listeners ---

  nextBtn.addEventListener("click", () => {
    moveToNext();
    stopAutoScroll(); // Stop auto-scroll on manual navigation
    startAutoScroll(); // Restart timer
  });

  prevBtn.addEventListener("click", () => {
    moveToPrev();
    stopAutoScroll(); // Stop auto-scroll on manual navigation
    startAutoScroll(); // Restart timer
  });

  carouselContainer.addEventListener("mouseenter", stopAutoScroll);
  carouselContainer.addEventListener("mouseleave", startAutoScroll);

  // --- Initialize ---
  startAutoScroll();
});
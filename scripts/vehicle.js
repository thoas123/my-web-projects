function saveInquiry(event, name, img, price) {
  event.preventDefault();

  const date = new Date().toLocaleDateString();

  // Create inquiry object
  const inquiry = {
    name: name,
    img: img,
    price: price,
    date: date,
    status: "Pending"
  };

  // Save to inquiries
  const inquiries = JSON.parse(localStorage.getItem("inquiries")) || [];
  inquiries.push(inquiry);
  localStorage.setItem("inquiries", JSON.stringify(inquiries));

  // Save to orders
  const orders = JSON.parse(localStorage.getItem("orders")) || [];
  orders.push(inquiry);
  localStorage.setItem("orders", JSON.stringify(orders));

  alert(`${name} has been added to your inquiries and orders.`);
}
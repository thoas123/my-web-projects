require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');


const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// --- Database Connection ---
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
}).promise();

// --- Middleware to protect routes ---
const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Not authorized, no token' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'a_default_secret_key'); // This line is the key
    req.user = decoded; // Adds user info (like id) to the request object
    next();
  } catch (error) {
    res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

// --- Middleware to check for admin role ---
const isAdmin = (req, res, next) => {
  // req.user is added by the 'protect' middleware
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    return res.status(403).json({ message: 'Not authorized as an admin' });
  }
};

// --- Auth Routes ---

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }

  try {
    const [userExists] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (userExists.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error during registration', error });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0 || !(await bcrypt.compare(password, users[0].password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: users[0].id, role: users[0].role }, process.env.JWT_SECRET || 'a_default_secret_key', { expiresIn: '1d' });
    res.json({ username: users[0].username, token, role: users[0].role });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login', error });
  }
});

// --- M-Pesa Integration ---

// Middleware to get M-Pesa access token
const getMpesaToken = async (req, res, next) => {
  const consumerKey = process.env.MPESA_CONSUMER_KEY;
  const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
  const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');

  try {
    const response = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
      headers: {
        Authorization: `Basic ${auth}`,
      },
    });
    req.mpesa_token = response.data.access_token;
    next();
  } catch (error) {
    console.error('M-Pesa Auth Error:', error.response ? error.response.data : error.message);
    res.status(500).json({ message: 'Failed to get M-Pesa token', error: error.message });
  }
};

// POST /api/mpesa/stk-push
app.post('/api/mpesa/stk-push', protect, getMpesaToken, async (req, res) => {
  const { amount, phone, orderId } = req.body;
  const token = req.mpesa_token;
  
  const shortcode = process.env.MPESA_BUSINESS_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;

  const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
  const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');

  const payload = {
    BusinessShortCode: shortcode,
    Password: password,
    Timestamp: timestamp,
    TransactionType: 'CustomerPayBillOnline',
    Amount: amount,
    PartyA: phone,
    PartyB: shortcode,
    PhoneNumber: phone,
    CallBackURL: `${process.env.MPESA_CALLBACK_URL}`,
    AccountReference: `ORDER-${orderId}`,
    TransactionDesc: `Payment for Order ${orderId}`,
  };

  try {
    const response = await axios.post('https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest', payload, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    res.status(200).json(response.data);
  } catch (error) {
    console.error('M-Pesa STK Push Error:', error.response ? error.response.data : error.message);
    res.status(500).json({ message: 'M-Pesa STK push failed', error: error.message });
  }
});

// POST /api/mpesa/callback - This is where Safaricom sends the payment result
app.post('/api/mpesa/callback', async (req, res) => {
  const callbackData = req.body.Body.stkCallback;
  console.log('M-Pesa Callback:', JSON.stringify(callbackData, null, 2));

  if (callbackData.ResultCode === 0) {
    // Payment was successful
    const orderId = callbackData.CallbackMetadata.Item.find(item => item.Name === 'AccountReference').Value.replace('ORDER-', '');
    // Update order status to 'Completed'
    await db.query('UPDATE orders SET status = "Completed" WHERE id = ?', [orderId]);
  }
  res.status(200).json({ message: 'Callback received' });
});

// Get all inquiries
app.get('/api/inquiries', protect, async (req, res) => {
  try {
    const [inquiries] = await db.query("SELECT *, DATE_FORMAT(date, '%Y-%m-%d') AS date FROM orders WHERE userId = ? ORDER BY id DESC", [req.user.id]);
    res.json(inquiries);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching inquiries', error });
  }
});

// Create a new inquiry and order
app.post('/api/inquiries', protect, async (req, res) => {
  try {
    const { name, img, price, date, status } = req.body;
    const inquiryData = { name, img, price, date, status, userId: req.user.id };

    await db.query('INSERT INTO orders SET ?', inquiryData);

    res.status(201).json({ message: 'Inquiry and order created successfully' });
  } catch (error) {
    console.error('Database insert error:', error); // Add this line for detailed logging
    res.status(500).json({ message: 'Error creating inquiry', error });
  }
});

// Cancel an inquiry
app.put('/api/inquiries/:id/cancel', protect, async (req, res) => {
    try {
        const { id } = req.params;
        await db.query('UPDATE orders SET status = "Canceled" WHERE id = ?', [id]);
        res.json({ message: 'Inquiry canceled' });
    } catch (error) {
        res.status(500).json({ message: 'Error canceling inquiry', error });
    }
});

// Get all orders
app.get('/api/orders', protect, async (req, res) => {
  try {
    const [orders] = await db.query("SELECT *, DATE_FORMAT(date, '%Y-%m-%d') AS date FROM orders WHERE userId = ? ORDER BY id DESC", [req.user.id]);
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error });
  }
});

// Cancel an order
app.put('/api/orders/:id/cancel', protect, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('UPDATE orders SET status = "Canceled" WHERE id = ? AND status = "Pending"', [id]);
    res.json({ message: 'Order canceled' });
  } catch (error) {
    res.status(500).json({ message: 'Error canceling order', error });
  }
});

// Get all orders (for admin)
app.get('/api/admin/orders', protect, isAdmin, async (req, res) => {
  try {
    // No WHERE clause, so it fetches all orders
    const query = `
      SELECT o.*, u.username, DATE_FORMAT(o.date, '%Y-%m-%d') AS date 
      FROM orders o
      LEFT JOIN users u ON o.userId = u.id
      ORDER BY o.id DESC`;
    const [orders] = await db.query(query);
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching all orders', error });
  }
});

// Approve an order (for admin)
app.put('/api/orders/:id/approve', protect, isAdmin, async (req, res) => { // Ensure isAdmin is used
  try {
    const { id } = req.params;
    await db.query('UPDATE orders SET status = "Approved" WHERE id = ? AND status = "Pending"', [id]);
    res.json({ message: 'Order approved' });
  } catch (error) {
    res.status(500).json({ message: 'Error approving order', error });
  }
});

// Complete an order (for admin)
app.put('/api/orders/:id/complete', protect, isAdmin, async (req, res) => { // Ensure isAdmin is used
  try {
    const { id } = req.params;
    await db.query('UPDATE orders SET status = "Completed" WHERE id = ? AND status = "Approved"', [id]);
    res.json({ message: 'Order completed' });
  } catch (error) {
    res.status(500).json({ message: 'Error completing order', error });
  }
});

// Remove an order
app.delete('/api/orders/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('DELETE FROM orders WHERE id = ?', [id]);
    res.json({ message: 'Order removed' });
  } catch (error) {
    res.status(500).json({ message: 'Error removing order', error });
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
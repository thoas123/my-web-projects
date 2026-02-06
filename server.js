require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Import mysql2/promise
const bcrypt = require('bcryptjs'); // Import bcryptjs for password hashing
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto'); // Import crypto for token generation
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const app = express();
app.use(cors());
app.use(express.json()); // Use express.json() instead of body-parser.json()

const passport = require('passport');
// Session Middleware for Passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET; // Use JWT_SECRET from .env
const API_BASE_URL = process.env.API_BASE_URL || `http://localhost:${PORT}`;

// Check for essential environment variables for a more helpful error message
if (!process.env.DB_DATABASE || !JWT_SECRET) {
  console.error("FATAL ERROR: Missing required environment variables (DB_DATABASE, JWT_SECRET). Please check your .env file.");
  process.exit(1);
}

// Database connection pool
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT || 3306
};

let db;

async function connectToDatabase() {
  try {
    db = await mysql.createPool(dbConfig);
    console.log('Connected to the MySQL database');
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1); // Exit process if database connection fails
  }
}

connectToDatabase(); // Establish database connection when server starts

// =======================
// PASSPORT CONFIGURATION
// =======================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    try {
      const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
      let user = users[0];

      if (user) {
        return done(null, user); // User found, proceed
      } else {
        // User not found, create a new user
        const [result] = await db.query(
          'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
          [email, '', 'user'] // No password for OAuth users
        );
        const newUser = { id: result.insertId, email: email, role: 'user' };
        return done(null, newUser);
      }
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const [users] = await db.query('SELECT id, email, role FROM users WHERE id = ?', [id]);
    done(null, users[0]);
  } catch (err) {
    done(err, null);
  }
});

// =======================
// AUTH ROUTES
// =======================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const payload = {
      id: user.id,
      email: user.email,
      role: user.role
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token: `Bearer ${token}`, role: user.role, message: 'Login successful' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const [existingUsers] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashedPassword, 'user']);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Failed to register user' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      // We send a success message even if the user doesn't exist to prevent email enumeration
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    // Generate a secure token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    const resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour

    await db.query('UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE id = ?', [resetPasswordToken, resetPasswordExpires, user.id]);

    // Simulate sending an email by logging the link to the console
    const resetUrl = `http://localhost:3000/reset-password.html?token=${resetToken}`;
    console.log('--- PASSWORD RESET ---');
    console.log(`A password reset was requested for ${user.email}.`);
    console.log(`Reset Link (valid for 1 hour): ${resetUrl}`);
    console.log('--------------------');

    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'An error occurred.' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const [users] = await db.query('SELECT * FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > ?', [hashedToken, Date.now()]);
    const user = users[0];

    if (!user) return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query('UPDATE users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE id = ?', [hashedPassword, user.id]);

    res.json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password.' });
  }
});

// =======================
// MIDDLEWARE
// =======================
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1] || authHeader;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Fetch the full user from the database to ensure data is fresh and secure
    const [users] = await db.query('SELECT id, email, role FROM users WHERE id = ?', [decoded.id]);
    const user = users[0];

    if (!user) {
      return res.status(401).json({ message: 'User not found, authorization denied' });
    }

    req.user = user; // Attach the full user object to the request
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// =======================
// USER ROUTES
// =======================
app.get('/api/inquiries', authMiddleware, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ message: 'Users only' });
  try {
    const [inquiries] = await db.query('SELECT * FROM orders WHERE userId = ?', [req.user.id]);
    res.json(inquiries);
  } catch (error) {
    console.error('Error fetching inquiries:', error);
    res.status(500).json({ message: 'Error fetching inquiries', error });
  }
});

app.post('/api/inquiries', authMiddleware, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ message: 'Users only' });
  const { name, img, price, date, status } = req.body; // status should be 'Pending' by default
  try {
    const [result] = await db.query('INSERT INTO orders (userId, name, img, price, date, status) VALUES (?, ?, ?, ?, ?, ?)', [req.user.id, name, img, price, date, status]);
    res.status(201).json({ message: 'Inquiry created', id: result.insertId });
  } catch (error) {
    console.error('Inquiry creation error:', error);
    res.status(500).json({ message: 'Error creating inquiry', error });
  }
});

app.get('/api/orders/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const [orders] = await db.query('SELECT status FROM orders WHERE id = ? AND userId = ?', [id, req.user.id]);
    if (orders.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json(orders[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching order status' });
  }
});

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const [notifications] = await db.query(
      'SELECT * FROM notifications WHERE userId = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(notifications);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Failed to fetch notifications' });
  }
});

app.delete('/api/notifications/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query(
      'DELETE FROM notifications WHERE id = ? AND userId = ?',
      [id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Notification not found or not authorized' });
    }
    res.json({ message: 'Notification deleted successfully' });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ message: 'Failed to delete notification' });
  }
});

app.delete('/api/notifications', authMiddleware, async (req, res) => {
  try {
    await db.query('DELETE FROM notifications WHERE userId = ?', [req.user.id]);
    res.json({ message: 'All notifications cleared successfully' });
  } catch (error) {
    console.error('Error clearing all notifications:', error);
    res.status(500).json({ message: 'Failed to clear all notifications' });
  }
});


app.put('/api/orders/:id/cancel', authMiddleware, async (req, res) => {
  const { id } = req.params;
  // This route can be used by either a user for their own order or an admin for any order.
  try {
    let result;
    if (req.user.role === 'admin') {
      [result] = await db.query('UPDATE orders SET status = "Canceled" WHERE id = ?', [id]);
    } else {
      [result] = await db.query('UPDATE orders SET status = "Canceled" WHERE id = ? AND userId = ?', [id, req.user.id]);
    }
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Order not found or cannot be canceled.' });
    res.json({ message: 'Order canceled successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to cancel order' });
  }
});

// =======================
// ADMIN ROUTES
// =======================
app.get('/api/admin/orders', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admins only' });
  try {
    const query = `
      SELECT o.*, u.email AS userEmail, DATE_FORMAT(o.date, '%Y-%m-%d') AS date 
      FROM orders o
      LEFT JOIN users u ON o.userId = u.id
      ORDER BY o.id DESC`;
    const [orders] = await db.query(query);
    res.json(orders);
  } catch (error) {
    console.error('Error fetching all orders:', error);
    res.status(500).json({ message: 'Error fetching all orders', error });
  }
});

app.put('/api/admin/orders/:id/approve', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admins only' });
  const { id } = req.params;
  try {
    const [result] = await db.query('UPDATE orders SET status = "Approved" WHERE id = ? AND status = "Pending"', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found or not in Pending status' });
    }
    res.json({ message: 'Order approved successfully' });
  } catch (error) {
    console.error('Error approving order:', error);
    res.status(500).json({ message: 'Error approving order', error });
  }
});

app.put('/api/admin/orders/:id/complete', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admins only' });
  const { id } = req.params;
  try {
    const [result] = await db.query('UPDATE orders SET status = "Completed" WHERE id = ? AND status = "Approved"', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found or not in Approved status' });
    }
    res.json({ message: 'Order completed successfully' });
  } catch (error) {
    console.error('Error completing order:', error);
    res.status(500).json({ message: 'Error completing order', error });
  }
});

app.get('/api/admin/messages', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admins only' });
  }
  try {
    const [messages] = await db.query('SELECT *, DATE_FORMAT(created_at, "%Y-%m-%d %H:%i") AS receivedDate FROM contact_messages ORDER BY id DESC');
    res.json(messages);
  } catch (error) {
    console.error('Error fetching contact messages:', error);
    res.status(500).json({ message: 'Error fetching messages' });
  }
});

// =======================
// CONTACT FORM ROUTE
// =======================
app.post('/api/contact', (req, res) => {
  try {
    const { name, email, message } = req.body;
    // Insert the message into the database
    db.query('INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)', [name, email, message]);
    res.status(200).json({ message: 'Thank you for your message! We will get back to you shortly.' });
  } catch (error) {
    console.error('Error saving contact message:', error);
    res.status(500).json({ message: 'Failed to send message.' });
  }
});

// =======================
// Start Google Login
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Callback URL
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (req, res) => {
    // On successful authentication, create a JWT for the user
    const payload = { id: req.user.id, email: req.user.email, role: req.user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    // Redirect to a page that can save the token to localStorage
    // The frontend will parse the token from the URL hash
    res.redirect(`${API_BASE_URL}/login.html#token=${token}&role=${req.user.role}`);
  }
);

// =======================
// M-PESA INTEGRATION
// =======================

/**
 * Helper function to initiate an M-Pesa STK Push request.
 * @param {number} orderId - The ID of the order.
 * @param {number} amount - The amount to be paid.
 * @param {string} phone - The customer's phone number (e.g., 2547xxxxxxxx).
 * @returns {Promise<object>} - The response from the M-Pesa API.
 */
async function initiateMpesaStkPush(orderId, amount, phone) {
  const shortcode = process.env.MPESA_BUSINESS_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;
  const callbackUrl = process.env.MPESA_CALLBACK_URL;
  const consumerKey = process.env.MPESA_CONSUMER_KEY;
  const consumerSecret = process.env.MPESA_CONSUMER_SECRET;

  if (!shortcode || !passkey || !callbackUrl || !consumerKey || !consumerSecret) {
    throw new Error('M-Pesa environment variables are not fully configured.');
  }

  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction && callbackUrl.includes('localhost')) {
    throw new Error('Invalid callback URL for production. Must be a public HTTPS URL.');
  }

  const now = new Date();
  const timestamp = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, '0'),
    String(now.getDate()).padStart(2, '0'),
    String(now.getHours()).padStart(2, '0'),
    String(now.getMinutes()).padStart(2, '0'),
    String(now.getSeconds()).padStart(2, '0')
  ].join('');

  const password = Buffer.from(shortcode + passkey + timestamp).toString('base64');

  const mpesaAuthUrl = isProduction
    ? 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    : 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

  const stkPushUrl = isProduction
    ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';

  // 1. Get Auth Token
  const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
  const tokenRes = await axios.get(mpesaAuthUrl, {
    headers: { Authorization: `Basic ${auth}` }
  });
  const accessToken = tokenRes.data.access_token;

  // 2. Prepare STK Push Request
  const cleanedAmount = String(amount || '0').replace(/[^0-9.]/g, '');
  const transactionAmount = Math.round(parseFloat(cleanedAmount));
  if (!transactionAmount || transactionAmount <= 0) {
    throw new Error('Invalid payment amount.');
  }

  const requestBody = {
    BusinessShortCode: shortcode,
    Password: password,
    Timestamp: timestamp,
    TransactionType: "CustomerPayBillOnline",
    Amount: transactionAmount,
    PartyA: phone,
    PartyB: shortcode,
    PhoneNumber: phone,
    CallBackURL: callbackUrl,
    AccountReference: `ORD-${orderId}`,
    TransactionDesc: `Payment for Order #${orderId}`
  };

  // 3. Send STK Push Request
  const stkRes = await axios.post(stkPushUrl, requestBody, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  });

  return stkRes.data;
}

app.post('/api/mpesa/stk-push', authMiddleware, async (req, res) => {
  const { amount, phone } = req.body;
  const orderId = parseInt(req.body.orderId, 10);

  if (isNaN(orderId)) {
    return res.status(400).json({ message: 'Invalid Order ID.' });
  }

  try {
    const mpesaResponse = await initiateMpesaStkPush(orderId, amount, phone);
    console.log(`STK Push sent for Order ${orderId}`);
    res.json({ CustomerMessage: mpesaResponse.CustomerMessage });
  } catch (err) {
    const errorMessage = err.response?.data?.errorMessage || err.message;
    console.error('STK Push Request Error:', errorMessage);
    if (err.response) {
      console.error('M-Pesa API Error Details:', JSON.stringify(err.response.data, null, 2));
    }
    res.status(500).json({
      message: 'STK Push failed',
      error: errorMessage
    });
  }
});

app.post('/api/mpesa/stk-callback', async (req, res) => {
  console.log("STK Callback Received:", JSON.stringify(req.body, null, 2));

  try {
    const callbackData = req.body?.Body?.stkCallback;

    if (!callbackData) {
      console.log("Callback missing 'stkCallback' body. Acknowledging receipt.");
      return res.status(200).json({ message: "OK" });
    }

    // Check if the payment was successful
    if (callbackData.ResultCode === 0) {
      const metadata = callbackData.CallbackMetadata?.Item || [];
      // Find the AccountReference which contains our Order ID
      const accountRefObject = metadata.find(item => item.Name === 'AccountReference');

      if (accountRefObject) {
        // Extract the numeric part of the order ID (e.g., from "ORD-123")
        const orderId = parseInt(accountRefObject.Value.replace(/\D/g, ''), 10);

        if (!isNaN(orderId)) {
          await db.query(
            'UPDATE orders SET status = "Completed" WHERE id = ? AND (status = "Approved" OR status = "Pending")',
            [orderId]
          );
          console.log("Order updated:", orderId);
        }
      }
    }

  } catch (error) {
    console.error('Error processing M-Pesa callback:', error);
  }

  // Always respond to Safaricom with a success message to prevent retries
  res.status(200).json({ message: 'Callback received' });
});
// =======================
// START SERVER
// =======================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

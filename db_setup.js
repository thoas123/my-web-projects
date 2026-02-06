require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

// Database configuration from your .env file
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 3306,
};

const dbName = process.env.DB_DATABASE;

// SQL statements to create the tables if they don't exist.
const usersTable = `
CREATE TABLE IF NOT EXISTS users (
  id INT NOT NULL AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'user',
  PRIMARY KEY (id),
  UNIQUE KEY email_UNIQUE (email)
);
`;

const ordersTable = `
CREATE TABLE IF NOT EXISTS orders (
  id INT NOT NULL AUTO_INCREMENT,
  userId INT NOT NULL,
  name VARCHAR(255) NOT NULL,
  img VARCHAR(255) DEFAULT NULL,
  price DECIMAL(10,2) NOT NULL,
  date DATE NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'Pending',
  PRIMARY KEY (id),
  KEY userId_fk_idx (userId),
  CONSTRAINT userId_fk FOREIGN KEY (userId) REFERENCES users (id) ON DELETE CASCADE
);
`;

const vehiclesTable = `
CREATE TABLE IF NOT EXISTS vehicles (
  id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  image_url VARCHAR(255) DEFAULT NULL,
  price DECIMAL(10,2) NOT NULL,
  PRIMARY KEY (id)
);
`;

const notificationsTable = `
CREATE TABLE IF NOT EXISTS notifications (
  id INT NOT NULL AUTO_INCREMENT,
  userId INT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_user_notification FOREIGN KEY (userId) REFERENCES users (id) ON DELETE CASCADE
);
`;
const contactMessagesTable = `
CREATE TABLE IF NOT EXISTS contact_messages (
  id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);
`;

async function setupDatabase() {
  let connection;
  try {
    // 1. Connect to MySQL server without specifying a database
    connection = await mysql.createConnection(dbConfig);
    console.log('Successfully connected to MySQL server.');

    // 2. Create the database if it doesn't exist
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\`;`);
    console.log(`Database '${dbName}' is ready.`);

    // 3. Close the initial connection and reconnect to the specific database
    await connection.end();
    connection = await mysql.createConnection({ ...dbConfig, database: dbName });
    console.log(`Successfully connected to database '${dbName}'.`);

    // 4. Create the tables
    await connection.query(usersTable);
    console.log('`users` table is ready.');
    await connection.query(ordersTable);
    console.log('`orders` table is ready.');
    await connection.query(vehiclesTable);
    console.log('`vehicles` table is ready.');
    await connection.query(notificationsTable);
    console.log('`notifications` table is ready.');
    await connection.query(notificationsTable);
    console.log('`notifications` table is ready.');
    await connection.query(contactMessagesTable);
    console.log('`contact_messages` table is ready.');

    // --- Automatic Schema Migration ---
    // Check if the 'email' column exists, and if not, try to migrate from 'username'.
    const [columns] = await connection.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'users' AND COLUMN_NAME = 'email'`,
      [dbName]
    );

    if (columns.length === 0) {
      console.log("Column 'email' not found. Attempting to migrate from 'username'...");
      await connection.query(`ALTER TABLE users CHANGE COLUMN username email VARCHAR(255) NOT NULL UNIQUE;`);
      console.log("Successfully migrated 'username' column to 'email'.");
    }
    // --- End of Migration ---

    // 5. Create a default admin user if one doesn't exist
    const adminEmail = 'otienothoas@gmail.com';
    const adminPassword = 'thoasAgola,123'; // Use a secure password in a real project

    const [adminExists] = await connection.query('SELECT * FROM users WHERE email = ?', [adminEmail]);

    if (adminExists.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await connection.query(
        'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
        [adminEmail, hashedPassword, 'admin']
      );
      console.log(`Default admin user created:`);
      console.log(`  Email: ${adminEmail}`);
      console.log(`  Password: ${adminPassword}`);
    } else {
      console.log('Admin user already exists.');
    }

    console.log('\n✅ Database setup complete!');

  } catch (error) {
    console.error('❌ Error setting up the database:', error.message);
  } finally {
    if (connection) {
      await connection.end();
      console.log('Connection closed.');
    }
  }
}

setupDatabase();

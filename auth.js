// File: auth.js

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require("express-rate-limit");
const fs = require('fs');
const https = require('https');

const app = express();
app.use(express.json()); // for parsing application/json

// HTTPS setup - Ensure to have your SSL certificates ready
const options = {
  key: fs.readFileSync('path/to/your-private-key.pem'),
  cert: fs.readFileSync('path/to/your-certificate.pem')
};

// Password hashing
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// JWT Token generation
function generateAuthToken(userId) {
  return jwt.sign({ userId: userId }, process.env.JWT_SECRET, { expiresIn: '30m' });
}

// Middleware for JWT validation
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // If there isn't any token

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // Limit each IP to 5 login requests per windowMs
});

// Mock user database - In real-world, use a proper database
let users = [
  { id: 1, username: "user1", password: "$2b$10$somehashedpassword" }
];

// Login route with rate limiting
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && await verifyPassword(password, user.password)) {
    const token = generateAuthToken(user.id);
    res.json({ token });
  } else {
    res.status(400).json({ message: 'Invalid Credentials' });
  }
});

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is protected', user: req.user });
});

// Register route (with password hashing)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ message: 'Username already taken' });
  }

  const hashedPassword = await hashPassword(password);
  const newUser = { id: users.length + 1, username, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: 'User registered successfully' });
});

// Start the server on HTTPS
https.createServer(options, app).listen(443, () => {
  console.log('Server running on port 443');
});

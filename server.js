require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
app.use(bodyParser.json());

// Initialize Passport middleware
app.use(passport.initialize());

// Secret key used for signing JWTs
const SECRET_KEY = process.env.SECRET_KEY || 'YOUR_SECRET_KEY';

// Dummy user store for demonstration purposes; replace this with your database integration.
const users = [
  {
    id: 1,
    username: 'user1',
    // This should be a bcrypt hash of the user's password.
    // For demonstration, assume "password123" hashed with bcrypt.
    passwordHash: '$2b$10$exampleHashedValueGoesHere'
  }
];

// ----------------------
// Traditional Login Flow
// ----------------------

// Endpoint: POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username or email
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Compare provided password with stored hash
  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Create a JWT token with user data and expiration (1 hour in this example)
  const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  // Expect header format: "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Protected Endpoint: GET /auth/me
app.get('/auth/me', verifyToken, (req, res) => {
  res.json({ user: req.user });
});

// --------------------------
// Google OAuth Flow via Passport
// --------------------------

// Configure Passport to use the Google OAuth strategy.
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,          // Set these in your .env file
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    // Here, you would typically search for the user in your database.
    // If the user exists, update their record if needed; if not, create a new user.
    // For demonstration purposes, we'll create a dummy user object based on the profile.
    const user = {
      id: profile.id,
      username: profile.displayName,
      email: profile.emails[0].value,
      provider: profile.provider
    };
    return done(null, user);
  }
));

// Route to initiate Google OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Callback URL that Google redirects to after user consent.
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication: generate your own JWT for the user.
    const user = req.user;
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    // Redirect to your UI application (or send the token as desired).
    res.redirect(`http://your-ui-app.com/login-success?token=${token}`);
  }
);

// --------------------------
// Start the Server
// --------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth microservice running on port ${PORT}`);
});

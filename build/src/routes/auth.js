const express = require('express');
const { SignJWT, importPKCS8 } = require('jose');
const fs = require('fs');
const path = require('path');

const router = express.Router();

// Load server private key
const serverPrivateKeyPem = fs.readFileSync(path.join(__dirname, '../../keys/server-private.pem'), 'utf8');

// Mock user database
const users = {
  'john.doe@orpheon.com': { password: 'password123', role: 'employee' },
  'admin@orpheon.com': { password: 'admin123', role: 'admin' }
};

// Login route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = users[email];
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT token
    const now = Math.floor(Date.now() / 1000);
    const serverPrivateKey = await importPKCS8(serverPrivateKeyPem, 'RS256');
    
    const token = await new SignJWT({
      sub: email,
      role: user.role,
      iat: now,
      exp: now + (24 * 60 * 60) // 24 hours
    })
    .setProtectedHeader({ 
      alg: 'RS256',
      typ: 'JWT',
      kid: 'rotate-2025-07'
    })
    .sign(serverPrivateKey);

    console.log(`[AUTH] User ${email} logged in with role: ${user.role}`);
    
    // Set JWT as HTTP-only cookie for web sessions
    res.cookie('jwt_token', token, {
      httpOnly: true,
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'lax'
    });
    
    // Redirect to documents page after successful login
    res.redirect('/documents');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login page
router.get('/login', (req, res) => {
  res.render('login', { 
    title: 'Login - Orphéon Sign',
    user: req.user || null
  });
});

// API login route (for testing)
router.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  try {
    const now = Math.floor(Date.now() / 1000);
    const serverPrivateKey = await importPKCS8(serverPrivateKeyPem, 'RS256');
    
    const token = await new SignJWT({
      sub: email,
      role: user.role,
      iat: now,
      exp: now + (24 * 60 * 60) // 24 hours
    })
    .setProtectedHeader({ 
      alg: 'RS256',
      typ: 'JWT',
      kid: 'rotate-2025-07'
    })
    .sign(serverPrivateKey);

    console.log(`[AUTH] User ${email} logged in with role: ${user.role}`);
    
    res.json({
      token,
      user: {
        email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout route
router.post('/logout', (req, res) => {
  res.clearCookie('jwt_token');
  res.redirect('/');
});

module.exports = router;

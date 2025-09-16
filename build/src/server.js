const express = require('express');
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');

// Import routes
const authRoutes = require('./routes/auth');
const documentRoutes = require('./routes/documents');
const adminRoutes = require('./routes/admin');

// Import middleware
const { authMiddleware } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3206;

// Load server keys
const serverPrivateKey = fs.readFileSync(path.join(__dirname, '../keys/server-private.pem'), 'utf8');
const serverPublicKey = fs.readFileSync(path.join(__dirname, '../keys/server-public.pem'), 'utf8');

// Make keys available globally
app.locals.serverPrivateKey = serverPrivateKey;
app.locals.serverPublicKey = serverPublicKey;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('combined'));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use('/static', express.static(path.join(__dirname, 'public')));

// Routes
app.use('/auth', authRoutes);
app.use('/documents', documentRoutes);
app.use('/admin', authMiddleware, adminRoutes);

// Home route
app.get('/', (req, res) => {
  res.render('index', { 
    title: 'Orphéon Sign',
    user: req.user || null
  });
});

// Test interface route
app.get('/test', (req, res) => {
  res.render('test', { 
    title: 'JWT Test Interface - Orphéon Sign',
    user: req.user || null
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).render('error', { 
    title: 'Error',
    message: 'An internal server error occurred',
    user: req.user || null
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', { 
    title: 'Not Found',
    message: 'The requested page was not found',
    user: req.user || null
  });
});

app.listen(PORT, () => {
  console.log(`Orphéon Sign server running on port ${PORT}`);
  console.log(`Access the application at: http://localhost:${PORT}`);
});

module.exports = app;

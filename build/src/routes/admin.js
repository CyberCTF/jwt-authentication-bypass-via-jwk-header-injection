const express = require('express');
const { requireAdmin, logAdminAction } = require('../middleware/auth');

const router = express.Router();

// Sensitive webhook secret
const ORPHEON_WHSEC_LIVE = 'whsec_live_7e1c1c0b7b0b45cda0a9d0f2b6c2b0a9b3d4c8e7a1f2c3b4d5e6f7a8b9c0d1';

// Admin dashboard
router.get('/', requireAdmin, (req, res) => {
  const stats = {
    totalUsers: 42,
    activeDocuments: 156,
    signedThisMonth: 89,
    pendingSignatures: 12
  };

  res.render('admin/dashboard', {
    title: 'Admin Dashboard - Orphéon Sign',
    user: req.user,
    stats: stats
  });
});

// Integrations page
router.get('/integrations', requireAdmin, (req, res) => {
  res.render('admin/integrations', {
    title: 'Integrations - Orphéon Sign',
    user: req.user,
    webhookSecret: ORPHEON_WHSEC_LIVE
  });
});

// Copy webhook secret
router.post('/integrations/webhook/copy', requireAdmin, (req, res) => {
  logAdminAction('copy_webhook_secret', req.user.sub, req);
  
  res.json({
    message: 'Webhook secret copied to clipboard',
    secret: ORPHEON_WHSEC_LIVE
  });
});

// Download .env file
router.get('/export/env', requireAdmin, (req, res) => {
  logAdminAction('download_env_file', req.user.sub, req);
  
  const envContent = `ORPHEON_WHSEC_LIVE=${ORPHEON_WHSEC_LIVE}`;
  
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename=".env"');
  res.send(envContent);
});

// Members management
router.get('/members', requireAdmin, (req, res) => {
  const members = [
    { id: 1, email: 'john.doe@orpheon.com', role: 'employee', status: 'active', lastLogin: '2024-01-22' },
    { id: 2, email: 'admin@orpheon.com', role: 'admin', status: 'active', lastLogin: '2024-01-22' },
    { id: 3, email: 'jane.smith@orpheon.com', role: 'employee', status: 'active', lastLogin: '2024-01-21' },
    { id: 4, email: 'bob.wilson@orpheon.com', role: 'employee', status: 'inactive', lastLogin: '2024-01-15' }
  ];

  res.render('admin/members', {
    title: 'Members Management - Orphéon Sign',
    user: req.user,
    members: members
  });
});

// Retention policy
router.get('/retention', requireAdmin, (req, res) => {
  const policies = [
    { type: 'signed_documents', retention: '7 years', status: 'active' },
    { type: 'draft_documents', retention: '1 year', status: 'active' },
    { type: 'audit_logs', retention: '3 years', status: 'active' },
    { type: 'user_sessions', retention: '30 days', status: 'active' }
  ];

  res.render('admin/retention', {
    title: 'Retention Policy - Orphéon Sign',
    user: req.user,
    policies: policies
  });
});

module.exports = router;

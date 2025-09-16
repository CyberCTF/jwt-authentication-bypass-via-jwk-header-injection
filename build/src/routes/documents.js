const express = require('express');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

// Mock document data
const documents = [
  {
    id: 'DOC-001',
    title: 'Q4 Financial Report',
    type: 'PDF',
    size: '2.4 MB',
    status: 'signed',
    uploadedAt: '2024-01-15',
    signedAt: '2024-01-16'
  },
  {
    id: 'DOC-002',
    title: 'Employee Handbook 2024',
    type: 'PDF',
    size: '1.8 MB',
    status: 'pending',
    uploadedAt: '2024-01-20',
    signedAt: null
  },
  {
    id: 'DOC-003',
    title: 'Contract Amendment - Tech Team',
    type: 'PDF',
    size: '856 KB',
    status: 'signed',
    uploadedAt: '2024-01-18',
    signedAt: '2024-01-19'
  },
  {
    id: 'DOC-004',
    title: 'Privacy Policy Update',
    type: 'PDF',
    size: '1.2 MB',
    status: 'draft',
    uploadedAt: '2024-01-22',
    signedAt: null
  }
];

// Documents page (requires authentication)
router.get('/', authMiddleware, (req, res) => {
  const stats = {
    total: documents.length,
    signed: documents.filter(doc => doc.status === 'signed').length,
    pending: documents.filter(doc => doc.status === 'pending').length,
    draft: documents.filter(doc => doc.status === 'draft').length
  };

  res.render('documents', {
    title: 'Documents - Orphéon Sign',
    user: req.user,
    documents: documents,
    stats: stats
  });
});

// Download document (mock)
router.get('/:id/download', authMiddleware, (req, res) => {
  const document = documents.find(doc => doc.id === req.params.id);
  
  if (!document) {
    return res.status(404).json({ error: 'Document not found' });
  }

  // Mock download - in real app, this would serve the actual file
  res.json({
    message: `Download initiated for ${document.title}`,
    document: document
  });
});

module.exports = router;

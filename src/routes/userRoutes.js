import express from 'express';
import { verifyToken, requireRole } from '../middlewares/authMiddleware.js';

const router = express.Router();

// only logged-in user can access
router.get('/profile', verifyToken, requireRole('user'), (req, res) => {
  res.status(200).json({ 
    message: 'Welcome to your profile', 
    userData: req.user 
  });
});

// A route strictly for admins
router.get('/admin/dashboard', verifyToken, requireRole('admin'), (req, res) => {
  res.status(200).json({ 
    message: 'Welcome to the Admin Dashboard. Highly classified data here.' 
  });
});

export default router;
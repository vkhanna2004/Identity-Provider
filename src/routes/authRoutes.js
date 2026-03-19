import express from 'express';
import AuthController from '../controllers/authController.js';
import createRateLimiter from '../middlewares/rateLimiter.js';

const router = express.Router();

// 3 attempts per hour (3600s) for registration
const registerLimiter = createRateLimiter('register', 3, 3600, 'Too many accounts created from this IP. Try again later.');

// 5 attempts per 15 mins (900s) for login
const loginLimiter = createRateLimiter('login', 5, 900, 'Too many login attempts. Please try again in 15 minutes.');

router.post('/register', registerLimiter, AuthController.register);
router.post('/login', loginLimiter, AuthController.login);
router.post('/refresh-token', AuthController.refreshToken);
router.post('/logout', AuthController.logout);

export default router;
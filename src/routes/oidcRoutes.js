import express from 'express';
import OIDCDiscoveryController from '../controllers/oidcDiscoveryController.js';
import OIDCController from '../controllers/oidcController.js';
import UserInfoController from '../controllers/userInfoController.js';
import { verifyToken } from '../middlewares/authMiddleware.js';
import createRateLimiter from '../middlewares/rateLimiter.js';

const router = express.Router();

// Limiters for OIDC endpoints
const tokenLimiter = createRateLimiter('oidc-token', 10, 900, 'Too many token requests. Please try again in 15 minutes.');
const authorizeLimiter = createRateLimiter('oidc-auth', 10, 900, 'Too many authorization requests. Please try again in 15 minutes.');

// OIDC Discovery & JWKS
router.get('/openid-configuration', OIDCDiscoveryController.getConfiguration);
router.get('/jwks.json', OIDCDiscoveryController.getJwks);

// OAuth2/OIDC Flows
router.get('/authorize', OIDCController.getAuthorize);
router.post('/authorize', verifyToken, authorizeLimiter, OIDCController.postAuthorize);
router.post('/token', tokenLimiter, OIDCController.postToken);

// UserInfo
router.get('/userinfo', UserInfoController.getUserInfo);

export default router;

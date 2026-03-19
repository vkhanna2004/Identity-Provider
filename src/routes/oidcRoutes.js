import express from 'express';
import OIDCDiscoveryController from '../controllers/oidcDiscoveryController.js';
import OIDCController from '../controllers/oidcController.js';
import UserInfoController from '../controllers/userInfoController.js';
import { verifyToken } from '../middlewares/authMiddleware.js';

const router = express.Router();

// OIDC Discovery & JWKS
router.get('/.well-known/openid-configuration', OIDCDiscoveryController.getConfiguration);
router.get('/jwks.json', OIDCDiscoveryController.getJwks);

// OAuth2/OIDC Flows
router.get('/authorize', OIDCController.getAuthorize);
router.post('/authorize', verifyToken, OIDCController.postAuthorize);
router.post('/token', OIDCController.postToken);

// UserInfo
router.get('/userinfo', UserInfoController.getUserInfo);

export default router;

import jwt from 'jsonwebtoken'
import redisClient from '../config/redis.js';

export const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    
    // Check if token is blacklisted (Revocation)
    if (decoded.jti) {
      const isBlacklisted = await redisClient.get(`blacklist:${decoded.jti}`);
      if (isBlacklisted) {
        return res.status(403).json({ error: 'Token has been revoked.' });
      }
    }

    req.user = decoded; 
    next(); 
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

export const requireRole = (requiredRole) => {
  return (req, res, next) => {
    if (!req.user || !req.user.roles.includes(requiredRole)) {
      return res.status(403).json({ error: `Access denied. Requires '${requiredRole}' role.` });
    }
    next();
  };
};

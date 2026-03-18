import redisClient from "../config/redis.js";

// A factory function that generates a customized rate limiter
const createRateLimiter = (prefix, limit, windowSeconds, customMessage) => {
  return async (req, res, next) => {
    try {
      const ip = req.ip || req.connection.remoteAddress;
      const key = `${prefix}:${ip}`;

      const requests = await redisClient.incr(key);

      if (requests === 1) {
        await redisClient.expire(key, windowSeconds);
      }

      if (requests > limit) {
        return res.status(429).json({ error: customMessage });
      }

      next();
    } catch (error) {
      console.error(`Redis Rate Limiter Error (${prefix}):`, error);
      next(); // Fail open so users aren't blocked if Redis crashes
    }
  };
};

export default createRateLimiter;
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import UserRepository from '../repositories/userRepository.js';
import TokenRepository from '../repositories/tokenRepository.js';
import redisClient from '../config/redis.js';

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME_MINUTES = 15;

class AuthService {
  /**
   * Hashes a password and creates a new user in the database.
   */
  static async registerUser(email, plainTextPassword) {
    const existingUser = await UserRepository.findUserByEmail(email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(plainTextPassword, saltRounds);

    try {
      const newUser = await UserRepository.createUser(email, passwordHash);
      return newUser;
    } catch (error) {
      // Handle race condition where user is created between our check and our insert
      if (error.code === '23505') { // PostgreSQL unique_violation code
        throw new Error('User already exists');
      }
      throw error;
    }
  }

  /**
   * Verifies credentials and generates JWTs.
   */
  static async loginUser(email, plainTextPassword) {
    const user = await UserRepository.findUserByEmail(email);
    if (!user) {
      throw new Error('Invalid email or password'); 
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const remainingTime = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      throw new Error(`Account is temporarily locked. Try again in ${remainingTime} minutes.`);
    }

    const isMatch = await bcrypt.compare(plainTextPassword, user.password_hash);
    if (!isMatch) {
      // Handle failed attempt
      await UserRepository.incrementFailedAttempts(user.id);
      
      const updatedUser = await UserRepository.findUserByEmail(email);
      if (updatedUser.failed_login_attempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date();
        lockUntil.setMinutes(lockUntil.getMinutes() + LOCK_TIME_MINUTES);
        await UserRepository.lockAccount(user.id, lockUntil);
        throw new Error(`Account locked due to too many failed attempts. Try again in ${LOCK_TIME_MINUTES} minutes.`);
      }
      
      throw new Error('Invalid email or password');
    }

    const roles = await UserRepository.getUserRoles(user.id);
    return await this.generateTokens(user.id, user.email, roles);
  }

  /**
   * Generates a pair of access and refresh tokens and stores the hashed refresh token in DB and Redis.
   */
  static async generateTokens(userId, email, roles) {
    const accessToken = jwt.sign(
      { userId, email, roles },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Store in Database (Source of Truth)
    await TokenRepository.createRefreshToken(userId, tokenHash, expiresAt);

    // Store in Redis (Performance Cache Layer)
    const redisKey = `session:${userId}:${tokenHash}`;
    try {
      await redisClient.set(redisKey, 'active', {
        EX: 7 * 24 * 60 * 60 // 7 days
      });
    } catch (err) {
      console.error('Redis Error:', err);
    }

    return { accessToken, refreshToken, userId };
  }

  /**
   * Verifies the refresh token, checks Redis/DB, and issues new tokens (Rotation).
   */
  static async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

      // Check Redis Cache First
      const redisKey = `session:${decoded.userId}:${tokenHash}`;
      let cachedSession = null;
      try {
        cachedSession = await redisClient.get(redisKey);
      } catch (err) {
        console.error('Redis Error:', err);
      }

      if (!cachedSession) {
        // If not in Redis, check DB
        const storedToken = await TokenRepository.findRefreshTokenByHash(tokenHash);

        if (!storedToken || storedToken.revoked) {
        // Reuse detection: If a revoked token is used, someone might have stolen it.
        // Revoke all tokens for this user as a security measure.
          if (storedToken?.revoked) {
            await this.revokeAllSessions(decoded.userId);
            throw new Error('Token has been revoked. All sessions invalidated for security.');
          }
          throw new Error('Invalid refresh token');
        }

        if (new Date(storedToken.expires_at) < new Date()) {
          throw new Error('Refresh token expired');
        }
      }

      // Token Rotation: Revoke current token and issue new ones
      const storedToken = await TokenRepository.findRefreshTokenByHash(tokenHash);
      if (storedToken) {
        await TokenRepository.revokeRefreshToken(storedToken.id);
      }

      // Remove from Redis
      try {
        await redisClient.del(redisKey);
      } catch (err) {
        console.error('Redis Error:', err);
      }

      // Issue new tokens
      const user = await UserRepository.findUserById(decoded.userId);
      if (!user) {
        throw new Error('User not found');
      }
      const roles = await UserRepository.getUserRoles(decoded.userId);

      return await this.generateTokens(decoded.userId, user.email, roles);
    } catch (error) {
      throw error;
    }
  }

  /**
   * Revokes all sessions for a user (DB and Redis).
   */
  static async revokeAllSessions(userId) {
    await TokenRepository.revokeAllUserTokens(userId);

    try {
      const keys = await redisClient.keys(`session:${userId}:*`);
      if (keys.length > 0) {
        await redisClient.del(keys);
      }
    } catch (err) {
      console.error('Redis Error:', err);
    }
  }

  /**
   * Revokes a specific refresh token (Logout).
   */
  static async logout(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      const storedToken = await TokenRepository.findRefreshTokenByHash(tokenHash);

      if (storedToken) {
        await TokenRepository.revokeRefreshToken(storedToken.id);
      }

      const redisKey = `session:${decoded.userId}:${tokenHash}`;
      try {
        await redisClient.del(redisKey);
      } catch (err) {
        console.error('Redis Error:', err);
      }
    } catch (error) {
      console.error('Logout Error:', error);
    }
  }

  static async getUserRoles(userId) {
    return await UserRepository.getUserRoles(userId);
  }
}

export default AuthService;
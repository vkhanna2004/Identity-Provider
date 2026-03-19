import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import UserRepository from '../repositories/userRepository.js';
import TokenRepository from '../repositories/tokenRepository.js';

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

    const newUser = await UserRepository.createUser(email, passwordHash);
    return newUser;
  }

  /**
   * Verifies credentials and generates JWTs.
   */
  static async loginUser(email, plainTextPassword) {
    const user = await UserRepository.findUserByEmail(email);
    if (!user) {
      throw new Error('Invalid email or password'); 
    }

    const isMatch = await bcrypt.compare(plainTextPassword, user.password_hash);
    if (!isMatch) {
      throw new Error('Invalid email or password');
    }

    const roles = await UserRepository.getUserRoles(user.id);
    return await this.generateTokens(user.id, user.email, roles);
  }

  /**
   * Generates a pair of access and refresh tokens and stores the hashed refresh token.
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

    await TokenRepository.createRefreshToken(userId, tokenHash, expiresAt);

    return { accessToken, refreshToken, userId };
  }

  /**
   * Verifies the refresh token, checks the DB, and issues new tokens (Rotation).
   */
  static async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

      const storedToken = await TokenRepository.findRefreshTokenByHash(tokenHash);

      if (!storedToken) {
        throw new Error('Invalid refresh token');
      }

      if (storedToken.revoked) {
        // Reuse detection: If a revoked token is used, someone might have stolen it.
        // Revoke all tokens for this user as a security measure.
        await TokenRepository.revokeAllUserTokens(decoded.userId);
        throw new Error('Token has been revoked. All sessions invalidated for security.');
      }

      if (new Date(storedToken.expires_at) < new Date()) {
        throw new Error('Refresh token expired');
      }

      // Token Rotation: Revoke current token and issue new ones
      await TokenRepository.revokeRefreshToken(storedToken.id);

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
   * Revokes a refresh token (Logout).
   */
  static async logout(refreshToken) {
    try {
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      const storedToken = await TokenRepository.findRefreshTokenByHash(tokenHash);

      if (storedToken) {
        await TokenRepository.revokeRefreshToken(storedToken.id);
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
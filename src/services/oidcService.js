import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import keyManager from '../utils/keyManager.js';
import ClientRepository from '../repositories/clientRepository.js';
import OAuthRepository from '../repositories/oauthRepository.js';
import UserRepository from '../repositories/userRepository.js';
import TokenRepository from '../repositories/tokenRepository.js';
import redisClient from '../config/redis.js';

class OIDCService {
  /**
   * Generates a set of OIDC tokens (access, id_token, refresh).
   */
  static async generateTokens(userId, clientId, scopes) {
    await keyManager.initialize();
    
    const user = await UserRepository.findUserById(userId);
    if (!user) throw new Error('User not found');

    const issuer = process.env.ISSUER || 'http://localhost:3000';
    const now = Math.floor(Date.now() / 1000);

    // ID Token Payload
    const idTokenPayload = {
      iss: issuer,
      sub: user.id,
      aud: clientId,
      iat: now,
      exp: now + 3600, // 1 hour
      auth_time: now,
    };

    if (scopes.includes('email')) {
      idTokenPayload.email = user.email;
      idTokenPayload.email_verified = true;
    }

    if (scopes.includes('profile')) {
      idTokenPayload.name = user.email.split('@')[0]; // Mocked profile info
    }

    // Access Token (can be a standard JWT or opaque)
    // For OIDC, making it a JWT allows other services to verify it via JWKS.
    const accessTokenPayload = {
      jti: crypto.randomBytes(16).toString('hex'), // Unique token ID
      iss: issuer,
      sub: user.id,
      aud: clientId,
      iat: now,
      exp: now + 900, // 15 mins
      scopes: scopes,
      roles: await UserRepository.getUserRoles(user.id)
    };

    // Sign tokens with RSA private key
    const privateKey = keyManager.getPrivateKey();
    const kid = keyManager.getKid();
    const idToken = jwt.sign(idTokenPayload, privateKey, { algorithm: 'RS256', keyid: kid });
    const accessToken = jwt.sign(accessTokenPayload, privateKey, { algorithm: 'RS256', keyid: kid });

    // Refresh Token
    const refreshToken = jwt.sign(
      { jti: crypto.randomBytes(16).toString('hex'), userId, clientId },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Store in Database
    await TokenRepository.createRefreshToken(userId, tokenHash, expiresAt);

    // Store in Redis
    const redisKey = `session:${userId}:${tokenHash}`;
    await redisClient.set(redisKey, 'active', {
      EX: 7 * 24 * 60 * 60 // 7 days
    });

    return {
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900
    };
  }

  /**
   * Generates a temporary authorization code.
   */
  static async generateAuthCode(userId, clientId, redirectUri, scopes) {
    const code = crypto.randomBytes(32).toString('hex');
    const data = { userId, clientId, redirectUri, scopes };
    await OAuthRepository.storeAuthCode(code, data);
    return code;
  }

  /**
   * Exchanges an authorization code for tokens.
   */
  static async exchangeCode(code, clientId, clientSecret, redirectUri) {
    const codeData = await OAuthRepository.getAndRemoveAuthCode(code);
    if (!codeData) {
      throw new Error('Invalid or expired authorization code');
    }

    if (codeData.clientId !== clientId) {
      throw new Error('Client ID mismatch');
    }

    if (codeData.redirectUri !== redirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // Client Secret validation (if provided)
    if (clientSecret) {
      const client = await ClientRepository.findByClientId(clientId);
      if (!client) throw new Error('Client not found');
      
      const hashedProvidedSecret = crypto.createHash('sha256').update(clientSecret).digest('hex');
      
      // Compare hex buffers securely
      const isMatch = crypto.timingSafeEqual(
          Buffer.from(hashedProvidedSecret, 'hex'),
          Buffer.from(client.client_secret_hash, 'hex')
      );

      if (!isMatch) throw new Error('Invalid client secret');
    }

    return await this.generateTokens(codeData.userId, codeData.clientId, codeData.scopes);
  }
}

export default OIDCService;

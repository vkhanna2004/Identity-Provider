import db from "../config/db.js";

class TokenRepository {
  /**
   * Stores a new refresh token
   * @param {string} userId 
   * @param {string} tokenHash 
   * @param {Date} expiresAt 
   */
  static async createRefreshToken(userId, tokenHash, expiresAt) {
    const query = `
      INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const result = await db.query(query, [userId, tokenHash, expiresAt]);
    return result.rows[0];
  }

  /**
   * Finds a refresh token by its hash
   * @param {string} tokenHash 
   */
  static async findRefreshTokenByHash(tokenHash) {
    const query = `
      SELECT * FROM refresh_tokens
      WHERE token_hash = $1;
    `;
    const result = await db.query(query, [tokenHash]);
    return result.rows[0] || null;
  }

  /**
   * Marks a refresh token as revoked
   * @param {string} tokenId 
   */
  static async revokeRefreshToken(tokenId) {
    const query = `
      UPDATE refresh_tokens
      SET revoked = TRUE
      WHERE id = $1;
    `;
    await db.query(query, [tokenId]);
  }

  /**
   * Revokes all tokens for a specific user
   * @param {string} userId 
   */
  static async revokeAllUserTokens(userId) {
    const query = `
      UPDATE refresh_tokens
      SET revoked = TRUE
      WHERE user_id = $1;
    `;
    await db.query(query, [userId]);
  }

  /**
   * Deletes expired tokens (cleanup)
   */
  static async deleteExpiredTokens() {
    const query = `
      DELETE FROM refresh_tokens
      WHERE expires_at < NOW();
    `;
    await db.query(query);
  }
}

export default TokenRepository;

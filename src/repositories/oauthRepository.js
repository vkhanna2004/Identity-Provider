import redisClient from '../config/redis.js';

class OAuthRepository {
  /**
   * Stores an authorization code in Redis
   * @param {string} code 
   * @param {Object} data 
   * @param {number} expiresInSeconds 
   */
  static async storeAuthCode(code, data, expiresInSeconds = 600) {
    const redisKey = `auth_code:${code}`;
    await redisClient.set(redisKey, JSON.stringify(data), {
      EX: expiresInSeconds
    });
  }

  /**
   * Retrieves and deletes an authorization code from Redis (one-time use)
   * @param {string} code 
   * @returns {Promise<Object|null>}
   */
  static async getAndRemoveAuthCode(code) {
    const redisKey = `auth_code:${code}`;
    const data = await redisClient.get(redisKey);
    if (data) {
      await redisClient.del(redisKey);
      return JSON.parse(data);
    }
    return null;
  }
}

export default OAuthRepository;

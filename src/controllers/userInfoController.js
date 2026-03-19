import jwt from 'jsonwebtoken';
import keyManager from '../utils/keyManager.js';
import UserRepository from '../repositories/userRepository.js';

class UserInfoController {
  static async getUserInfo(req, res) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'invalid_token' });
    }

    const token = authHeader.split(' ')[1];

    try {
      await keyManager.initialize();
      const publicKey = keyManager.getPublicKey();
      
      const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
      
      const user = await UserRepository.findUserById(decoded.sub);
      if (!user) {
        return res.status(401).json({ error: 'invalid_token' });
      }

      // Standard OIDC claims
      const userInfo = {
        sub: user.id,
        email: user.email,
        email_verified: true,
      };

      if (decoded.scopes && decoded.scopes.includes('profile')) {
        userInfo.name = user.email.split('@')[0];
      }

      res.json(userInfo);
    } catch (error) {
      res.status(401).json({ error: 'invalid_token', error_description: error.message });
    }
  }
}

export default UserInfoController;

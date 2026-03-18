import AuthService from '../services/authService.js';
import jwt from 'jsonwebtoken'

class AuthController {
  static async register(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }

      const newUser = await AuthService.registerUser(email, password);

      return res.status(201).json({
        message: 'User registered successfully',
        user: newUser
      });
    } catch (error) {
      if (error.message === 'User already exists') {
        return res.status(409).json({ error: error.message });
      }
      console.error('Registration Error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async login(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }

      const tokens = await AuthService.loginUser(email, password);

      return res.status(200).json({
        message: 'Login successful',
        ...tokens
      });
    } catch (error) {
      if (error.message === 'Invalid email or password') {
        return res.status(401).json({ error: error.message });
      }
      console.error('Login Error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token is required' });
      }

      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      // TODO you would also check if this token 
      // is stored in the database and hasn't been revoked.

      const newAccessToken = jwt.sign(
        { userId: decoded.userId, email: decoded.email, roles: decoded.roles },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '15m' }
      );

      return res.status(200).json({
        message: 'Token rotated successfully',
        accessToken: newAccessToken
      });
    } catch (error) {
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }
  }
}

export default AuthController;
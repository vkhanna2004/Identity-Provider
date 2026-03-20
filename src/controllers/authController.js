import AuthService from '../services/authService.js';

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

      const tokens = await AuthService.refreshToken(refreshToken);

      return res.status(200).json({
        message: 'Token rotated successfully',
        ...tokens
      });
    } catch (error) {
      if (error.message.includes('revoked') || error.message.includes('security')) {
        return res.status(401).json({ error: error.message });
      }
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }
  }

  static async logout(req, res) {
    try {
      const { refreshToken } = req.body;
      const accessToken = req.headers.authorization?.split(' ')[1];

      if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token is required' });
      }

      await AuthService.logout(refreshToken, accessToken);

      return res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      console.error('Logout Error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
}

export default AuthController;
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import UserRepository from '../repositories/userRepository.js';

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

    // Generate Tokens
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, roles: roles }, 
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' } 
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' } // Long-lived refresh token
    );

    //TODO -  hash the refreshToken and store it in the refresh_tokens table here. 

    return { accessToken, refreshToken, userId: user.id };
  }

  static async getUserRoles(userId) {
    const query = `
      SELECT r.name 
      FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1;
    `;
    const result = await db.query(query, [userId]);
    return result.rows.map(row => row.name); 
  }
}

export default AuthService;
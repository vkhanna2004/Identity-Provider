import db from "../config/db.js";

class UserRepository {
  /**
   * Finds a user by their ID
   * @param {string} id 
   * @returns {Promise<Object|null>} The user object or null
   */
  static async findUserById(id) {
    const query = `
      SELECT id, email, created_at 
      FROM users 
      WHERE id = $1;
    `;
    const result = await db.query(query, [id]);
    return result.rows[0] || null;
  }

  /**
   * Finds a user by their email address
   * @param {string} email 
   * @returns {Promise<Object|null>} The user object or null
   */
  static async findUserByEmail(email) {
    const query = `
      SELECT id, email, password_hash, created_at 
      FROM users 
      WHERE email = $1;
    `;
    const result = await db.query(query, [email]);
    return result.rows[0] || null;
  }

  /**
   * Creates a new user and assigns them the default 'user' role
   * @param {string} email 
   * @param {string} passwordHash 
   * @returns {Promise<Object>} The created user (without password hash)
   */
  static async createUser(email, passwordHash) {
    const client = await db.getClient();
    
    try {
      await client.query('BEGIN');

      const insertUserQuery = `
        INSERT INTO users (email, password_hash) 
        VALUES ($1, $2) 
        RETURNING id, email, created_at;
      `;
      const userResult = await client.query(insertUserQuery, [email, passwordHash]);
      const newUser = userResult.rows[0];

      const roleResult = await client.query('SELECT id FROM roles WHERE name = $1', ['user']);
      const defaultRoleId = roleResult.rows[0].id;

      const assignRoleQuery = `
        INSERT INTO user_roles (user_id, role_id) 
        VALUES ($1, $2);
      `;
      await client.query(assignRoleQuery, [newUser.id, defaultRoleId]);

      await client.query('COMMIT');
      
      return newUser;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Retrieves roles for a specific user
   * @param {string} userId 
   * @returns {Promise<string[]>} Array of role names
   */
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

export default UserRepository;
import db from "../config/db.js";

class ClientRepository {
  /**
   * Finds a client by their client_id
   * @param {string} clientId 
   * @returns {Promise<Object|null>}
   */
  static async findByClientId(clientId) {
    const query = `
      SELECT id, client_id, client_secret_hash, client_name, redirect_uris, grant_types, allowed_scopes 
      FROM oauth_clients 
      WHERE client_id = $1;
    `;
    const result = await db.query(query, [clientId]);
    return result.rows[0] || null;
  }

  /**
   * Creates a new OAuth2 client
   * @param {Object} clientData 
   * @returns {Promise<Object>}
   */
  static async createClient(clientData) {
    const { clientId, clientSecretHash, clientName, redirectUris, grantTypes, allowedScopes } = clientData;
    const query = `
      INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, allowed_scopes)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `;
    const result = await db.query(query, [
      clientId, 
      clientSecretHash, 
      clientName, 
      JSON.stringify(redirectUris), 
      JSON.stringify(grantTypes || ["authorization_code", "refresh_token"]), 
      JSON.stringify(allowedScopes || ["openid", "profile", "email"])
    ]);
    return result.rows[0];
  }

  /**
   * Deletes a client
   * @param {string} clientId 
   */
  static async deleteClient(clientId) {
    const query = `DELETE FROM oauth_clients WHERE client_id = $1`;
    await db.query(query, [clientId]);
  }
}

export default ClientRepository;

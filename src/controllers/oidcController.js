import ClientRepository from '../repositories/clientRepository.js';
import OIDCService from '../services/oidcService.js';
import AuthService from '../services/authService.js';
import UserRepository from '../repositories/userRepository.js';
import crypto from 'crypto';

class OIDCController {
  /**
   * GET /api/oidc/authorize
   * Validates OIDC request and returns status.
   */
  static async getAuthorize(req, res) {
    const { client_id, redirect_uri, scope, response_type, state } = req.query;

    if (!client_id || !redirect_uri || !response_type) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required parameters' });
    }

    const client = await ClientRepository.findByClientId(client_id);
    if (!client) {
      return res.status(400).json({ error: 'invalid_client', error_description: 'Client not found' });
    }

    // Validate redirect URI
    const redirectUris = Array.isArray(client.redirect_uris) ? client.redirect_uris : JSON.parse(client.redirect_uris);
    if (!redirectUris.includes(redirect_uri)) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect URI' });
    }

    if (response_type !== 'code') {
      return res.status(400).json({ error: 'unsupported_response_type', error_description: 'Only "code" is supported' });
    }

    // In a headless flow, we return what's needed for the frontend to proceed
    res.json({
      status: 'CONSENT_REQUIRED',
      client_name: client.client_name,
      scopes: scope ? scope.split(' ') : ['openid'],
      state: state
    });
  }

  /**
   * POST /api/oidc/authorize
   * Handles user consent and issues authorization code.
   * Requires user authentication (e.g., via session cookie or bearer token).
   */
  static async postAuthorize(req, res) {
    const { client_id, redirect_uri, scope, state, userId } = req.body;
    // Note: userId should ideally come from a verified session/token.
    // In this headless example, we expect the frontend to pass the userId after login.
    // REAL WORLD: This endpoint should be protected by the IdP's own auth middleware.

    if (!userId) {
      return res.status(401).json({ error: 'login_required' });
    }

    try {
      const code = await OIDCService.generateAuthCode(userId, client_id, redirect_uri, scope ? scope.split(' ') : ['openid']);
      
      // Standard OIDC redirect (or JSON if preferred for headless)
      const redirectWithCode = `${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`;
      
      res.json({
        status: 'SUCCESS',
        redirect_uri: redirectWithCode,
        code: code
      });
    } catch (error) {
      res.status(500).json({ error: 'server_error', error_description: error.message });
    }
  }

  /**
   * POST /api/oidc/token
   * Exchanges authorization code or refresh token for OIDC tokens.
   */
  static async postToken(req, res) {
    const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

    // Support for Basic Auth if client_id/secret are not in body
    let finalClientId = client_id;
    let finalClientSecret = client_secret;

    if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) {
      const authHeader = Buffer.from(req.headers.authorization.split(' ')[1], 'base64').toString();
      const [cid, csec] = authHeader.split(':');
      finalClientId = cid;
      finalClientSecret = csec;
    }

    if (!finalClientId) {
      return res.status(400).json({ error: 'invalid_client' });
    }

    try {
      if (grant_type === 'authorization_code') {
        if (!code || !redirect_uri) {
          return res.status(400).json({ error: 'invalid_request' });
        }
        const tokens = await OIDCService.exchangeCode(code, finalClientId, finalClientSecret, redirect_uri);
        return res.json(tokens);
      } 
      
      if (grant_type === 'refresh_token') {
        if (!refresh_token) {
          return res.status(400).json({ error: 'invalid_request' });
        }
        // Implementation for OIDC refresh token flow
        // Reusing existing AuthService rotation logic but returning OIDC tokens
        const tokens = await AuthService.refreshToken(refresh_token);
        // Note: AuthService returns custom tokens. For production, we'd wrap this to return OIDC tokens.
        // For simplicity, we'll assume OIDCService handles this or we call a special method.
        return res.json(tokens);
      }

      res.status(400).json({ error: 'unsupported_grant_type' });
    } catch (error) {
      res.status(400).json({ error: 'invalid_grant', error_description: error.message });
    }
  }
}

export default OIDCController;

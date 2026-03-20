import keyManager from '../utils/keyManager.js';

class OIDCDiscoveryController {
  static async getConfiguration(req, res) {
    const issuer = process.env.ISSUER || `http://${req.headers.host}`;
    
    const configuration = {
      issuer: issuer,
      authorization_endpoint: `${issuer}/api/oidc/authorize`,
      token_endpoint: `${issuer}/api/oidc/token`,
      userinfo_endpoint: `${issuer}/api/oidc/userinfo`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ["code", "id_token", "token id_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      claims_supported: ["sub", "iss", "aud", "exp", "iat", "email", "profile"]
    };

    res.json(configuration);
  }

  static async getJwks(req, res) {
    await keyManager.initialize();
    res.json(keyManager.getJwks());
  }
}

export default OIDCDiscoveryController;

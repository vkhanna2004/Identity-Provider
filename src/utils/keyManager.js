import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

class KeyManager {
  constructor() {
    this.privateKey = null;
    this.publicKey = null;
    this.jwks = null;
    this.initialized = false;
  }

  /**
   * Initializes the RSA key pair from environment variables or generates a new one.
   */
  async initialize() {
    if (this.initialized) return;

    let privateKeyPem;

    if (process.env.RSA_PRIVATE_KEY) {
      // Decode from Base64 if it's stored that way
      privateKeyPem = Buffer.from(process.env.RSA_PRIVATE_KEY, 'base64').toString('utf8');
      if (!privateKeyPem.includes('BEGIN PRIVATE KEY')) {
        // Assume it's the raw PEM string if not base64 encoded as expected
        privateKeyPem = process.env.RSA_PRIVATE_KEY;
      }
    } else {
      console.warn('RSA_PRIVATE_KEY not found in environment. Generating a temporary key pair for development...');
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      this.initialized = true;
      this.generateJwks();
      return;
    }

    this.privateKey = privateKeyPem;
    this.publicKey = crypto.createPublicKey(this.privateKey).export({
      type: 'spki',
      format: 'pem'
    });

    this.initialized = true;
    this.generateJwks();
  }

  /**
   * Generates a JWKS (JSON Web Key Set) from the public key.
   */
  generateJwks() {
    const publicKeyObj = crypto.createPublicKey(this.publicKey);
    const jwk = publicKeyObj.export({ format: 'jwk' });

    const kid = crypto.createHash('sha256').update(this.publicKey).digest('hex').substring(0, 16); //key-id

    // Ensure kids/alg/use/typ are set for OIDC compliance
    this.jwks = {
      keys: [
        {
          ...jwk,
          kid: kid,
          use: 'sig',
          alg: 'RS256'
        }
      ]
    };
    this.kid = kid;
  }

  getKid() {
    return this.kid;
  }

  getPrivateKey() {
    return this.privateKey;
  }

  getPublicKey() {
    return this.publicKey;
  }

  getJwks() {
    return this.jwks;
  }
}

const keyManager = new KeyManager();
export default keyManager;

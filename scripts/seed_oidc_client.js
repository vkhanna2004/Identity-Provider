import crypto from 'crypto';
import ClientRepository from '../src/repositories/clientRepository.js';

async function seedClient() {
  const clientId = 'test-client';
  const clientSecret = 'test-secret';
  const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

  const clientData = {
    clientId: clientId,
    clientSecretHash: clientSecretHash,
    clientName: 'Test OIDC Client',
    redirectUris: ['http://localhost:4000/callback'],
    grantTypes: ['authorization_code', 'refresh_token'],
    allowedScopes: ['openid', 'profile', 'email']
  };

  try {
    const existing = await ClientRepository.findByClientId(clientId);
    if (existing) {
      console.log('Client already exists.');
    } else {
      const newClient = await ClientRepository.createClient(clientData);
      console.log('Client seeded successfully:', newClient.client_id);
    }
  } catch (err) {
    console.error('Error seeding client:', err);
  } finally {
    process.exit();
  }
}

seedClient();

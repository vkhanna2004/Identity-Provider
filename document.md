
## Step-by-Step Flow

  1. Registration (POST /api/auth/register)
  The user creates an account directly with Identity Provider.
   * Request: Email and Password.
   * Action: Password is hashed and stored in the users table.
   * Result: User account is created.

  2. Login to IdP (POST /api/auth/login)
  Before a user can use OIDC to log into other apps, they must be authenticated by your IdP.
   * Request: Email and Password.
   * Action: IdP verifies credentials.
   * Result: Returns an accessToken and refreshToken. This establishes the user's "session" with the IdP.

  3. Start OIDC Authorization (GET /api/oidc/authorize)
  A third-party app (Client) wants to log the user in.
   * Request: client_id, redirect_uri, scope (e.g., openid profile email).
   * Action: Your IdP validates that the Client is registered and the redirect_uri is allowed.
   * Result: Returns CONSENT_REQUIRED. The UI should now show the user: "App X wants to access your profile. Allow?"

  4. Grant Consent (POST /api/oidc/authorize)
  The user clicks "Allow" on the consent screen.
   * Request: client_id, userId, scope.
   * Action: Your IdP generates a short-lived Authorization Code linked to that user.
   * Result: Returns a redirect_uri containing the code (e.g., https://client-app.com/callback?code=AUTH_CODE_123).

  5. Exchange Code for Tokens (POST /api/oidc/token)
  The Client app (behind the scenes) exchanges the code for actual identity tokens.
   * Request: grant_type=authorization_code, code=AUTH_CODE_123, client_secret.
   * Action: Your IdP validates the code and the client's secret.
   * Result: Returns:
       * id_token: A JWT containing the user's identity information (name, email).
       * access_token: To access protected APIs (like /userinfo).
       * refresh_token: To get new tokens without asking the user to log in again.

  6. Logout (POST /api/auth/logout)
  The user ends their session with the IdP.
   * Request: refreshToken.
   * Action: Your IdP invalidates the session tokens in the database/Redis.
   * Result: The user is logged out of the IdP. Note that they might still be logged into the third-party app until
     their id_token expires or the app's own session ends.

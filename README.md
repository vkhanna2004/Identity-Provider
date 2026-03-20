# Centralized Identity Provider (IdP) & OIDC Server 🔐

A high-performance, enterprise-grade authentication and authorization service built with Node.js. This service functions as a standalone Identity Provider (IdP) supporting OpenID Connect (OIDC) standards, session management, and granular security controls.

## What does this project do
This project serves as a central "Source of Truth" for identity across multiple applications. Instead of each app building its own login system, they delegate authentication to this server. It handles user registration, secure OIDC flows (Authorization Code), issues signed JWTs (ID & Access Tokens), and provides a standardized UserInfo endpoint.

## Key Features
* **Full OIDC Support:** Implements OpenID Connect Authorization Code flow with standard Discovery (`/.well-known/openid-configuration`) and JWKS (`/jwks.json`) endpoints.
* **Cryptographic Security:** Uses RSA-256 for token signing with dynamic Key ID (`kid`) support for seamless 3rd party verification.
* **Advanced Token Lifecycle:** 
    * **Rotation:** Short-lived Access Tokens (15m) and long-lived Refresh Tokens (7d).
    * **Immediate Revocation:** Real-time Access Token blacklisting using `jti` (JWT ID) stored in Redis upon logout.
    * **Reuse Detection:** Automatic invalidation of all sessions if a revoked refresh token is reused.
* **Multi-Layered Protection:** 
    * **Rate Limiting:** IP-based request throttling using Redis to prevent brute-force and DoS attacks.
    * **Account Lockout:** Database-level lockout (5 failed attempts) to protect specific user accounts.
* **Database Layer:** Clean architecture using raw, parameterized PostgreSQL queries (no ORM) for maximum performance and SQL injection prevention.
* **API Documentation:** Fully documented via Swagger UI at `/api-docs`.

## Prerequisites
* **Node.js:** v20+
* **Docker & Docker Compose:** For running local PostgreSQL and Redis instances.
* **RSA Key Pair:** Required for OIDC signing (the server can auto-generate a temporary pair for development).

## Quick Start 

1. Clone the repository.
2. Create a `.env` file based on the provided configuration.
3. Spin up the infrastructure:
  ```bash
   docker-compose up -d
  ```
4. Run the initial database migration:
  ```bash
  docker exec -i idp_postgres psql -U admin -d idp_database < database/migrations/001_initial_schema.sql
  ```
5. Seed a Test Client:                                                                 
```bash                                                                                 
node scripts/seed_oidc_client.js                                                                      
  ```
6. Install dependencies and start the server:
```bash
npm install
node server.js
```
## API Documentation
Interactive API documentation is provided via Swagger UI. Once the server is running, navigate to:
http://localhost:3000/api-docs 


## Testing with Postman
1. **Discovery:** `GET /.well-known/openid-configuration`
2. **Register/Login:** `POST /api/auth/register` and `POST /api/auth/login`
3. **OIDC Flow:** Use the `test-client` credentials to initiate `/api/oidc/authorize` and exchange the code via `/api/oidc/token`.

## Project Structure

```text
├── src/
│   ├── config/          # DB and Redis connection pools
│   ├── controllers/     # OIDC, Auth, and User controllers
│   ├── middlewares/     # JWT verification (with Blacklist check), RBAC, Rate Limiting
│   ├── repositories/    # Raw SQL repositories (User, Client, Token, OAuth)
│   ├── routes/          # Express router definitions
│   ├── services/        # OIDC logic, Auth logic, and Token generation
│   └── utils/           # KeyManager (RSA/JWKS)
├── scripts/             # Seeding and utility scripts
├── database/migrations  # PostgreSQL schema definitions
└── swagger.yaml         # OpenAPI specification
```


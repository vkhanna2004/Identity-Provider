# Authentication Service (IdP) 🔐

A standalone Node.js backend service that handles user authentication, session management, and role-based access control. Built with a focus on clean architecture, raw SQL relational integrity, and API security.

## What does this project do
This project is a standalone login and security system. Instead of every application building its own authentication, they rely on this central service. It registers users, securely hashes passwords, issues digital ID badges (tokens), blocks brute-force bot attacks, and ensures users only access what their specific role allows.

## Key Features
* **Authentication & Authorization:** Secure user registration and login utilizing `bcryptjs` for password hashing and JWTs for stateless session management.
* **Token Rotation:** Implements short-lived Access Tokens (15m) and long-lived Refresh Tokens (7d) to balance security with user experience.
* **Role-Based Access Control (RBAC):** Custom middleware to protect routes based on user roles embedded within the token payload.
* **Database Layer:** Uses raw, parameterized PostgreSQL queries via a connection pool to enforce data integrity and prevent SQL injection, completely bypassing ORMs.
* **Rate Limiting:** Utilizes Redis to track and limit API requests (e.g., login attempts) to mitigate brute-force attacks.
* **Security Hardening:** Implements `helmet` for HTTP header security and standardized JSON error handling.

## Prerequisites
* **Node.js:** v18+
* **Docker & Docker Compose:** For running local PostgreSQL and Redis instances.

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
5.Install dependencies and start the server:
```bash
npm install
node server.js
```
## API Documentation
Interactive API documentation is provided via Swagger UI. Once the server is running, navigate to:
http://localhost:3000/api-docs 


## Project Structure

```text
├── src/
│   ├── config/          # DB and Redis connection pools
│   ├── controllers/     # Request parsing and response handling
│   ├── middlewares/     # JWT verification, RBAC, Rate Limiting, Error Handling
│   ├── repositories/    # Raw SQL queries
│   ├── routes/          # Express router definitions
│   └── services/        # Cryptography and core business logic
├── database/            # Raw SQL migration scripts
├── docker-compose.yml   # Infrastructure definitions
└── swagger.yaml         # OpenAPI specification
```


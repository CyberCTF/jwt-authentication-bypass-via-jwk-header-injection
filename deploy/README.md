# Orphéon Sign - JWT Authentication Bypass Lab

## Overview

Orphéon Sign is a SaaS platform for electronic document workflow management. This lab demonstrates a critical JWT authentication bypass vulnerability through JWK header injection.

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd jwt-authentication-bypass-via-jwk-header-injection

# Start the application
docker-compose -f deploy/docker-compose.yml up --build

# Access the application
open http://localhost:3206
```

### Using Docker

```bash
# Build the image
docker build -f deploy/Dockerfile -t orpheon-sign .

# Run the container
docker run -p 3206:3206 orpheon-sign

# Access the application
open http://localhost:3206
```

## Application Features

- **Document Management**: Upload, view, and track document signatures
- **User Authentication**: JWT-based authentication with role-based access control
- **Admin Portal**: Restricted administrative interface for system management
- **Integration Management**: Webhook configuration and API key management

## Demo Credentials

- **Employee**: `john.doe@orpheon.com` / `password123`

## Security Vulnerability

This lab contains a deliberate JWT authentication bypass vulnerability:

- **Vulnerability**: JWK header injection in JWT verification
- **Impact**: Unauthorized access to admin functions
- **Target**: Access to webhook signing secrets

## Testing

Run the automated tests to verify the vulnerability:

```bash
# Install test dependencies
pip install -r test/requirements.txt

# Run tests (ensure the application is running)
python test/test_app.py
```

## Architecture

- **Backend**: Node.js 20 with Express.js
- **Authentication**: JWT with RS256 algorithm
- **Frontend**: EJS templates with TailwindCSS
- **Database**: In-memory data (no persistent storage)

## Security Considerations

⚠️ **This is a deliberately vulnerable application designed for educational purposes only.**

- Do not use in production environments
- Contains intentional security vulnerabilities
- Designed for cybersecurity training and research

## Support

For issues or questions about this lab, please refer to the main project documentation.

---

**Disclaimer**: This application is created solely for educational purposes to demonstrate JWT security vulnerabilities. It should never be deployed in production environments.

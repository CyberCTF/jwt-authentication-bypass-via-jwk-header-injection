# Orphéon Sign - JWT Authentication Bypass Lab

- **Goal**: sign in as an administrator (by bypassing authentication) to retrieve the **API key / integration secret** from the admin portal.

## Credentials 

- **Email**: `john.doe@orpheon.com`
- **Password**: `password123`

## Technologies used

- **Backend**: Node.js (Express.js)
- **Authentication**: JWT (RS256) with the `jose` library
- **Frontend**: EJS + TailwindCSS
- **Containerization**: Docker / Docker Compose

## Project structure

```
.
├── build/
│   ├── app/                    # Application source code
│   │   ├── keys/
│   │   │   ├── generate-keys.js
│   │   │   └── server-public.jwk
│   │   ├── src/
│   │   │   ├── middleware/
│   │   │   │   ├── auth.js
│   │   │   │   └── client-auth.js
│   │   │   ├── public/
│   │   │   ├── routes/
│   │   │   │   ├── admin.js
│   │   │   │   ├── auth.js
│   │   │   │   └── documents.js
│   │   │   ├── server.js
│   │   │   └── views/
│   │   │       ├── admin/
│   │   │       │   ├── dashboard.ejs
│   │   │       │   ├── integrations.ejs
│   │   │       │   ├── members.ejs
│   │   │       │   └── retention.ejs
│   │   │       ├── documents.ejs
│   │   │       ├── error.ejs
│   │   │       ├── index.ejs
│   │   │       ├── layout.ejs
│   │   │       ├── login.ejs
│   │   │       ├── partials/
│   │   │       │   ├── footer.ejs
│   │   │       │   └── header.ejs
│   │   │       └── test.ejs
│   │   ├── package.json
│   │   ├── package-lock.json
│   │   └── seed/
│   ├── Dockerfile              # Docker build file
│   └── node_modules/           # Dependencies (auto-generated)
├── deploy/
│   ├── docker-compose.dev.yml  # Development Docker Compose
│   └── README.md
├── docker-compose.yml          # Production Docker Compose
├── docs/
│   ├── done.md
│   └── WRITEUP.md
├── test/
│   ├── service1/
│   │   └── test_orpheon_sign.py
│   ├── main.py                 # Test entry point
│   └── requirements.txt
├── .gitignore
└── README.md
```

## Docker Usage

### Development
```bash
docker compose -f deploy/docker-compose.dev.yml up
```

### Production
```bash
docker compose up
```

## Testing
```bash
pytest test/main.py
```

## Educational disclaimer

This repository is a **deliberately vulnerable lab**, provided solely for educational and security research purposes. Do not use it in production, nor on publicly exposed environments. All use must take place within a legal and controlled setting.

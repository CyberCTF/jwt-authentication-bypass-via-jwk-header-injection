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
│   ├── keys/
│   │   ├── generate-keys.js
│   │   └── server-public.jwk
│   ├── node_modules/
│   ├── package-lock.json
│   ├── package.json
│   ├── seed/
│   └── src/
│       ├── middleware/
│       │   ├── auth.js
│       │   └── client-auth.js
│       ├── public/
│       ├── routes/
│       │   ├── admin.js
│       │   ├── auth.js
│       │   └── documents.js
│       ├── server.js
│       └── views/
│           ├── admin/
│           │   ├── dashboard.ejs
│           │   ├── integrations.ejs
│           │   ├── members.ejs
│           │   └── retention.ejs
│           ├── documents.ejs
│           ├── error.ejs
│           ├── index.ejs
│           ├── layout.ejs
│           ├── login.ejs
│           ├── partials/
│           │   ├── footer.ejs
│           │   └── header.ejs
│           └── test.ejs
├── deploy/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── README.md
├── docs/
│   ├── done.md
│   └── WRITEUP.md
├── README.md
└── test/
    ├── requirements.txt
    └── test_app.py
```

## Educational disclaimer

This repository is a **deliberately vulnerable lab**, provided solely for educational and security research purposes. Do not use it in production, nor on publicly exposed environments. All use must take place within a legal and controlled setting.

const { jwtVerify, importJWK, importSPKI } = require('jose');
const fs = require('fs');
const path = require('path');

// Load server public key
const serverPublicKeyPem = fs.readFileSync(path.join(__dirname, '../../keys/server-public.pem'), 'utf8');

// Admin actions logging
const adminActions = [];

const logAdminAction = (action, actor, req) => {
  const logEntry = {
    action,
    actor,
    timestamp: new Date().toISOString(),
    remoteIP: req.ip || req.connection.remoteAddress || '127.0.0.1'
  };
  adminActions.push(logEntry);
  console.log(`[ADMIN_ACTION] ${JSON.stringify(logEntry)}`);
};

// Make admin actions available globally
global.adminActions = adminActions;
global.logAdminAction = logAdminAction;

const authMiddleware = async (req, res, next) => {
  try {
    // Check for token in Authorization header first (for API calls)
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7); // Remove 'Bearer ' prefix
    }
    // Check for token in cookies (for web sessions)
    else if (req.cookies && req.cookies.jwt_token) {
      token = req.cookies.jwt_token;
    }
    
    if (!token) {
      // For web requests, redirect to login instead of returning JSON
      if (req.accepts('html')) {
        return res.redirect('/auth/login');
      }
      return res.status(401).json({ error: 'No token provided' });
    }
    
    // Decode the protected header to check for jwk
    const [headerB64] = token.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    
    let keySource = 'server_public_key';
    let verificationKey = await importSPKI(serverPublicKeyPem, 'RS256');
    let payload = null;
    
    // VULNERABILITY: If jwk is present in header, use it instead of server key
    if (header.jwk) {
      console.log(`[AUTH_MIDDLEWARE] JWK found in header, importing external key`);
      
      try {
        // Import the JWK from the header
        verificationKey = await importJWK(header.jwk, header.alg || 'RS256');
        keySource = 'header_jwk';
        
        console.log(`[AUTH_MIDDLEWARE] Successfully imported JWK from header`);
      } catch (error) {
        console.error(`[AUTH_MIDDLEWARE] Failed to import JWK from header:`, error.message);
        return res.status(401).json({ error: 'Invalid JWK in header' });
      }
    }
    
    // Explicitly reject jku and x5u (security measure)
    if (header.jku || header.x5u) {
      console.log(`[AUTH_MIDDLEWARE] Rejected token with jku/x5u header parameters`);
      return res.status(401).json({ error: 'jku and x5u are not allowed' });
    }

    // Verify the JWT
    const result = await jwtVerify(token, verificationKey, {
      algorithms: ['RS256']
    });
    payload = result.payload;

    // Log authentication details
    console.log(`[AUTH_MIDDLEWARE] alg: ${header.alg}, key_source: ${keySource}, sub: ${payload.sub}, role: ${payload.role}, result: success`);

    // Attach user info to request
    req.user = {
      sub: payload.sub,
      role: payload.role,
      keySource: keySource
    };

    next();
  } catch (error) {
    console.error(`[AUTH_MIDDLEWARE] Authentication failed:`, error.message);
    
    // Try to get header info for logging
    let headerInfo = 'unknown';
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const [headerB64] = token.split('.');
        const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
        headerInfo = header.alg || 'unknown';
      }
    } catch (e) {
      // Ignore parsing errors
    }
    
    console.log(`[AUTH_MIDDLEWARE] alg: ${headerInfo}, key_source: unknown, sub: unknown, role: unknown, result: failure`);
    
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

module.exports = { authMiddleware, requireAdmin, logAdminAction };

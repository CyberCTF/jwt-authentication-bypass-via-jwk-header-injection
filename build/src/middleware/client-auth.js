// Client-side authentication middleware
// This middleware adds the JWT token to requests automatically

const addAuthToken = (req, res, next) => {
  // This is a placeholder for client-side authentication
  // The actual token handling is done in the frontend JavaScript
  next();
};

module.exports = { addAuthToken };

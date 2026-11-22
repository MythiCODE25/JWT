const jwt = require("jsonwebtoken");

/**
 * JWT Authentication Middleware
 * Validates the presence and format of Bearer token from the Authorization header.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];

  if (!authHeader || typeof authHeader !== "string") {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Authorization header is missing",
    });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer" || !parts[1].trim()) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Authorization format must be: Bearer <token>",
    });
  }

  // Token extracted, proceed to verification in next phase
  req.token = parts[1].trim();
  next();
}

module.exports = { requireAuth };

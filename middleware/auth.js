const jwt = require("jsonwebtoken");

/**
 * JWT Authentication Middleware - requireAuth
 * Requirements:
 * - Read the JWT from the Authorization request header.
 * - Accept tokens in format: Authorization: Bearer <token>
 * - Verify the token using the secret stored in JWTSECRET environment variable.
 * - If the token is valid, attach its decoded payload to req.user and call next().
 * - If the token is missing, invalid, or expired, return an appropriate 401 Unauthorized response.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];

  if (!authHeader || typeof authHeader !== "string") {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Authorization token is missing",
    });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer" || !parts[1].trim()) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Invalid token format. Format must be: Bearer <token>",
    });
  }

  const token = parts[1].trim();
  const secret = process.env.JWTSECRET;

  try {
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
    return next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Token has expired",
      });
    }

    return res.status(401).json({
      error: "Unauthorized",
      message: "Invalid or malformed token",
    });
  }
}

module.exports = { requireAuth };

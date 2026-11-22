require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const prisma = require("./prismaClient");

const app = express();
const PORT = process.env.PORT || 3000;
const JWTSECRET = process.env.JWTSECRET;

if (!JWTSECRET) {
  console.warn("WARNING: JWTSECRET environment variable is not defined!");
}

// Middleware to parse incoming JSON requests
app.use(express.json());

// Basic health check endpoint
app.get("/", (req, res) => {
  res.status(200).json({ status: "OK", message: "JWT Authentication Service Running" });
});

// 1. User Registration – POST /signup
app.post("/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body || {};

    // Validate email and password presence and types
    if (
      !email ||
      typeof email !== "string" ||
      !password ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Email and password are required and must be strings",
      });
    }

    // Normalize email: trim leading/trailing spaces and convert to lowercase
    const normalizedEmail = email.trim().toLowerCase();

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!normalizedEmail || !emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "A valid email address is required",
      });
    }

    // Ensure the password contains at least 6 characters
    if (password.length < 6) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Password must be at least 6 characters long",
      });
    }

    // Check whether a user with the given email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (existingUser) {
      return res.status(409).json({
        error: "Conflict",
        message: "Email is already registered",
      });
    }

    // Hash the password using bcrypt with 10 salt rounds
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create the user in the database
    const newUser = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: typeof name === "string" && name.trim() ? name.trim() : null,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    // Generate a JWT containing the user's ID and email, with jti and 1h expiration
    const token = jwt.sign(
      {
        id: newUser.id,
        email: newUser.email,
      },
      JWTSECRET,
      {
        expiresIn: "1h",
        jwtid: crypto.randomUUID(),
      }
    );

    // Return the newly created user's details and JWT
    return res.status(201).json({
      message: "User registered successfully",
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      createdAt: newUser.createdAt,
      user: newUser,
      token,
      jwt: token,
    });
  } catch (error) {
    console.error("Error in /signup:", error);
    return res.status(500).json({
      error: "Internal Server Error",
      message: "An unexpected error occurred during registration",
    });
  }
});

// Start the server if executed directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

module.exports = app;

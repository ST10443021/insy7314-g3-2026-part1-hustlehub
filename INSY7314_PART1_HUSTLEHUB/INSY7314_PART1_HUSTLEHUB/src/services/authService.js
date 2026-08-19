const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const userModel = require('../models/userModel');

/**
 * Hash a plain-text password with bcrypt.
 * bcrypt automatically generates and stores a unique salt per password
 * inside the resulting hash, so no separate salt column is required.
 */
async function hashPassword(plainTextPassword) {
  return bcrypt.hash(plainTextPassword, config.bcryptSaltRounds);
}

/** Compare a plain-text password against a stored bcrypt hash. */
async function verifyPassword(plainTextPassword, passwordHash) {
  return bcrypt.compare(plainTextPassword, passwordHash);
}

/**
 * Issue a signed JWT for an authenticated user.
 * The payload intentionally carries only non-sensitive identifiers
 * (id, role) - never the password hash or email - since JWT payloads
 * are base64-encoded, not encrypted, and can be read by anyone holding
 * the token.
 */
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn, issuer: 'hustlehub-plus-api' }
  );
}

function verifyToken(token) {
  return jwt.verify(token, config.jwtSecret, { issuer: 'hustlehub-plus-api' });
}

async function registerUser({ email, password, role }) {
  const existing = userModel.findByEmail(email);
  if (existing) {
    const err = new Error('An account with this email already exists.');
    err.statusCode = 409;
    err.expose = true;
    throw err;
  }

  const passwordHash = await hashPassword(password);
  const user = userModel.create({ email, passwordHash, role });
  return userModel.toPublicUser(user);
}

async function loginUser({ email, password }) {
  // Generic failure message used for both "no such user" and "wrong password"
  // so the API never confirms or denies whether an email is registered
  // (this prevents user-enumeration attacks).
  const genericError = () => {
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    err.expose = true;
    return err;
  };

  const user = userModel.findByEmail(email);
  if (!user) throw genericError();

  const passwordMatches = await verifyPassword(password, user.passwordHash);
  if (!passwordMatches) throw genericError();

  const token = issueToken(user);
  return { token, user: userModel.toPublicUser(user) };
}

module.exports = {
  hashPassword,
  verifyPassword,
  issueToken,
  verifyToken,
  registerUser,
  loginUser,
};

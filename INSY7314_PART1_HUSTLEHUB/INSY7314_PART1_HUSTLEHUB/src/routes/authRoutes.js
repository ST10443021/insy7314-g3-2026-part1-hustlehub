const express = require('express');
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController');
const { registerValidationRules, loginValidationRules } = require('../middleware/validators');
const { requireAuth } = require('../middleware/authMiddleware');

const router = express.Router();

// Throttles brute-force / credential-stuffing attempts against auth endpoints
// specifically (separate from the global limiter in app.js).
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many attempts. Please try again later.' },
});

router.post('/register', authLimiter, registerValidationRules, authController.register);
router.post('/login', authLimiter, loginValidationRules, authController.login);

// Protected route demonstrating JWT validation on every request.
router.get('/profile', requireAuth, authController.getProfile);

module.exports = router;

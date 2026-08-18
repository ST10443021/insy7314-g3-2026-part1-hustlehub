const bcrypt = require('bcrypt');
const crypto = require('crypto');
const userModel = require('../models/userModel');
const jwt = require('jsonwebtoken');

/**
 * Registers a new HustleHub+ user.
 *
 * The email address is normalised before storage so differently
 * capitalised versions of the same email cannot create duplicate
 * accounts. Existing emails and usernames are checked before the
 * account is created.
 *
 * bcrypt is used to securely hash the password before storage.
 * The original plaintext password is never stored or returned.
 * A safe user object without the password hash is returned after
 * successful registration.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
async function registerUser(username, email, password, role) {
    // Normalise the email to provide consistent storage and lookup.
    const normalisedEmail = email.trim().toLowerCase();

    // Prevent more than one account from using the same email address.
    const existingEmail = userModel.findByEmail(normalisedEmail);

    if (existingEmail) {
        const error = new Error('Email already registered');
        error.statusCode = 409;
        throw error;
    }

    // Prevent duplicate usernames from being registered.
    const existingUsername = userModel.findByUsername(username);

    if (existingUsername) {
        const error = new Error('Username already registered');
        error.statusCode = 409;
        throw error;
    }

    /*
     * bcrypt hashes the user's password before it reaches the data
     * storage layer. Ten salt rounds are used to make password hashing
     * computationally expensive while remaining suitable for the
     * application's authentication requirements.
     */
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    /*
     * A UUID is generated for each user so accounts have a unique
     * identifier that can later be referenced by the JWT and protected
     * profile functionality.
     */
    const newUser =
    {
        id: crypto.randomUUID(),
        username,
        email: normalisedEmail,
        password: hashedPassword,
        role,
        createdAt: new Date().toISOString()
    };

    // Store only the user record containing the hashed password.
    userModel.createUser(newUser);

    /*
     * Create a safe representation of the user before returning it.
     * The password field is deliberately excluded so that even the
     * bcrypt hash is never exposed in an API response.
     */
    const safeUser =
    {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt
    };

    return safeUser;

}

/**
 * Authenticates an existing HustleHub+ user.
 *
 * The supplied email is normalised before searching for the account.
 * bcrypt.compare() securely compares the submitted plaintext password
 * with the stored bcrypt hash without decrypting the stored password.
 *
 * Both an unknown email address and an incorrect password return the
 * same generic error message. This helps prevent user enumeration by
 * avoiding confirmation of whether a particular account exists.
 *
 * After successful authentication, a signed JWT containing only the
 * agreed non-sensitive identity claims is generated. The JWT secret
 * and expiry are loaded from environment variables rather than being
 * hardcoded in the source code.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
async function loginUser(email, password) {
    // Normalise the email so login lookup matches registration storage.
    const normalisedEmail = email.trim().toLowerCase();

    const user = userModel.findByEmail(normalisedEmail);

    /*
     * A generic authentication error is deliberately used instead of
     * revealing whether the supplied email address exists.
     */
    if (!user) {
        const error = new Error('Invalid email or password');
        error.statusCode = 401;
        throw error;
    }

    /*
     * Compare the supplied password against the stored bcrypt hash.
     * The stored password is never decrypted or converted back into
     * plaintext.
     */
    const isMatch = await bcrypt.compare(password, user.password);

    /*
     * Use the same response as an unknown email to prevent attackers
     * from identifying registered accounts through different errors.
     */
    if (!isMatch) {
        const error = new Error('Invalid email or password');
        error.statusCode = 401;
        throw error;
    }

    /*
     * Sign a JWT containing only the agreed identity information.
     * Sensitive fields such as the password and email are excluded
     * from the token payload. jsonwebtoken automatically adds the
     * issued-at and expiry claims.
     *
     * JWT_SECRET and JWT_EXPIRES_IN are read from environment variables
     * so secrets and security configuration are not hardcoded.
     */
    const token = jwt.sign(
        {
            id: user.id,
            username: user.username,
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: process.env.JWT_EXPIRES_IN
        }
    );

    /*
     * Return only non-sensitive user information alongside the JWT.
     * The stored password hash is deliberately excluded.
     */
    const safeUser =
    {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
    };

    return {
        token,
        user: safeUser
    };
}

module.exports = {
    registerUser,
    loginUser
};
const authService = require('../services/authService');
const userModel = require('../models/userModel');

/**
 * Handles user registration requests.
 * Extracts the required registration details from the request body and
 * passes them to the authentication service where the registration
 * business logic and password hashing are performed.
 *
 * The controller does not perform security logic itself, which keeps
 * authentication responsibilities separated between the controller
 * and service layers.
 *
 * Any errors are forwarded to the centralised error-handling middleware
 * using next(error), preventing raw errors or stack traces from being
 * returned directly to the client.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
async function register(req, res, next) {
    try {
        const { username, email, password, role } = req.body;

        const user = await authService.registerUser(
            username,
            email,
            password,
            role
        );

        return res.status(201).json({
            success: true,
            data: user
        });
    }
    catch (error) {
        next(error);
    }
}

/**
 * Handles user login requests.
 * Passes the supplied email and password to the authentication service,
 * where the stored password hash is checked and a JWT is generated
 * when authentication succeeds.
 *
 * The controller only manages the HTTP request and response flow and
 * does not perform password comparison or token generation itself.
 *
 * Any authentication errors are forwarded to the centralised error
 * handler to ensure that sensitive internal information is not exposed.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
async function login(req, res, next) {
    try {
        const { email, password } = req.body;

        const result = await authService.loginUser(email, password);

        return res.status(200).json({
            success: true,
            data: result
        });
    }
    catch (error) {
        next(error);
    }
}

/**
 * Returns the authenticated user's profile information.
 * The JWT middleware verifies the token before this controller executes
 * and attaches the decoded token payload to req.user.
 *
 * The user's ID is then used to retrieve the full user record from the
 * model. A safe user object is created so that the stored password hash
 * is never included in the API response.
 *
 * Any errors are forwarded to the centralised error-handling middleware.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
function getProfile(req, res, next) {
    try {
        const user = userModel.findById(req.user.id);

        if (!user) {
            const error = new Error('User not found');
            error.statusCode = 404;
            throw error;
        }

        const safeUser = {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            createdAt: user.createdAt
        };

        return res.status(200).json({
            success: true,
            data: safeUser
        });
    }
    catch (error) {
        next(error);
    }
}

module.exports = {
    register,
    login,
    getProfile
};
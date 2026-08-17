const authService = require('../services/authService');
const userModel = require('../models/userModel');

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


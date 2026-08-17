const bcrypt = require('bcrypt');
const crypto = require('crypto');
const userModel = require('../models/userModel');
const jwt = require('jsonwebtoken');

async function registerUser(username, email, password, role)
{
    const normalisedEmail = email.trim().toLowerCase();

    const existingEmail = userModel.findByEmail(normalisedEmail);

    if (existingEmail)
    {
        const error = new Error('Email already registered');
        error.statusCode = 409;
        throw error;
    }

    const existingUsername = userModel.findByUsername(username);

    if (existingUsername)
    {
        const error = new Error('Username already registered');
        error.statusCode = 409;
        throw error;
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser =
    {
        id: crypto.randomUUID(),
        username,
        email: normalisedEmail,
        password: hashedPassword,
        role,
        createdAt: new Date().toISOString()
    };

    userModel.createUser(newUser);

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

async function loginUser(email, password) {
    const normalisedEmail = email.trim().toLowerCase();

    const user = userModel.findByEmail(normalisedEmail);

    if (!user) {
        const error = new Error('Invalid email or password');
        error.statusCode = 401;
        throw error;
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        const error = new Error('Invalid email or password');
        error.statusCode = 401;
        throw error;
    }

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
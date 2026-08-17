const bcrypt = require('bcrypt');
const crypto = require('crypto');
const userModel = require('../models/userModel');

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

module.exports = {
    registerUser
};
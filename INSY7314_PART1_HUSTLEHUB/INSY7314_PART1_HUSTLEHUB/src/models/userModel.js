/**
 * Temporary in-memory user storage used for Part 1 of HustleHub+.
 *
 * A permanent database is not required during this stage of the
 * project, so users are stored in memory while the secure backend
 * authentication foundation is developed.
 *
 * This model is responsible only for data storage and retrieval.
 * Authentication logic such as password hashing, password comparison,
 * and JWT generation remains in the service layer.
 *
 * Author: BLAKE GODFREY - ST10435415
 */

// Temporary in-memory user storage for Part 1.
// MongoDB/database persistence will be introduced in a later stage.
const users = [];

/**
 * Adds a new user record to the in-memory user collection.
 * The service layer is responsible for ensuring that the password
 * has already been securely hashed before this function is called.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
function createUser(user) {
    users.push(user);
    return user;
}

/**
 * Searches for a user using their email address.
 * This helper is used during registration to detect duplicate emails
 * and during login to locate the account being authenticated.
 *
 * Returns undefined when no matching user exists.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
function findByEmail(email) {
    return users.find(user => user.email === email);
}

/**
 * Searches for a user using their username.
 * This allows the registration service to prevent duplicate usernames
 * from being created.
 *
 * Returns undefined when no matching user exists.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
function findByUsername(username) {
    return users.find(user => user.username === username);
}

/**
 * Searches for a user using their unique ID.
 * This is primarily used by the protected profile functionality after
 * the JWT middleware has authenticated the request and supplied the
 * user's ID through req.user.
 *
 * Returns undefined when no matching user exists.
 *
 * Author: BLAKE GODFREY - ST10435415
 */
function findById(id) {
    return users.find(user => user.id === id);
}

module.exports = {
    createUser,
    findByEmail,
    findByUsername,
    findById
};
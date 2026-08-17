// Temporary in-memory user storage for Part 1.
// MongoDB/database persistence will be introduced in a later stage.
const users = [];
function createUser(user)
{
    users.push(user);
    return user;
}
function findByEmail(email)
{
    return users.find(user => user.email === email);
}
function findByUsername(username)
{
    return users.find(user => user.username === username);
}
function findById(id)
{
    return users.find(user => user.id === id);
}

module.exports = {
    createUser,
    findByEmail,
    findByUsername,
    findById
};

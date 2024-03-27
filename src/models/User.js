const mongoose = require('mongoose');

const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: [true, "Username is required!"]
    },
    password: {
        type: String,
        required: [true, "Password is required!"]
    },
}, { timestamp: true });

const User = mongoose.model("User", UserSchema);

module.exports = User;
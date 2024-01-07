const mongoose = require('mongoose');


const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "A user should have a name"],
    },
    email: {
        type: String,
        required: [true, 'A user should have an email'],
        unique: true,
        lowercase: true,
    },
    photo: String,
    password: {
        type: String,
        required: [true, "Please provide a password"],
        minlength:  8
    },
    passwordConfirm: {
        type: String,
        required: [true, "Please confirm your password"]
    }
})


const User = mongoose.model('User', userSchema);

module.exports = User;
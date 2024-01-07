const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs')

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
        minlength:  8,
        select: false
    },
    passwordConfirm: {
        type: String,
        required: [true, "Please confirm your password"],
        validate: {
            validator: function(el) {
                return el === this.password;
            },
            message: "passwords are not the same"
        }
    }
})


userSchema.pre('save', async (next) => {
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 12)
    this.passwordConfirm = undefined

    next()
})

userSchema.method.correctPassword = function(candidatePassword, userPassword) {
    return bcrypt.compare(candidatePassword, userPassword)
}

const User = mongoose.model('User', userSchema);

module.exports = User;
const {promisify} = require('util');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const jwt = require('jsonwebtoken')
const AppError = require('./errorController')

const signToken = async (user) => {
    const token = jwt.sign({
        id: user._id,
    }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN});

    return token
}

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });

    const token = signToken(newUser)

    res.status(201).json({
        status: 'success',
        token,
        data: {
            user: newUser
        }
    })
});

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body.email;

    if (!email || !password) {
        return next(new AppError('Please provide email and password', 400))
    }

    const user = await User.findOne({ email: email }).select('+password')

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new AppError("Incorrect email or password", 401));
    }

    const token = signToken(user._id);

    res.status(200).json({
        status: 'success',
        token
    })
})

exports.protect = catchAsync(async (req, res, next) => {
    let token
    if (req.headers.authorization && req.headers.startWith('Bearer')) {
        [, token] = req.headers.authorization.split(' ')
    }

    if (!token) {
        return next(new AppError('You are not logged in! please login to get access'), 401)
    }

   const decoded = promisify(await jwt.verify(token,  process.env.JWT_SECRET));

   const freshUser = await User.findById(decoded.id);

   if (!freshUser) {
    return next(new AppError('The user belonging to token does not exists anymore'), 401)
   }

   if (freshUser.passwordChangedAt(decoded.iat)){
    return next(new AppError('User recently changed password please login again', 401))
   }

   req.user = freshUser;
   next()
})

exports.restrictTO = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new AppError('You do not have permission to perform this action', 403))
        }

        next();
    }
}
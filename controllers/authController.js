const crypto = require('crypto')
const {promisify} = require('util');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const jwt = require('jsonwebtoken')
const AppError = require('./../utils/appError')
const sendEmail = require('./../utils/email')

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    res.cookie('jwt', token, {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        )
    })
}

const signToken = async (user) => {
    const token = jwt.sign({
        id: user._id,
    }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN});

    return token
}

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });

    createSendToken(newUser, 200, res)
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

    createSendToken(req.user, 200, res)
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

exports.forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return next(new AppError('There is no user with this email address', 404));
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your Password? ${resetURL}`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Password Reset Token (valid for 10 minutes)',
            message,
        });

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email!',
        });
    } catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError('There was an error sending the email. Please try again.', 500));
    }
});


exports.resetPassword = catchAsync(async (req, res, next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: {$gt: Date.now() }});

    if (!user) {
        return next(new AppError('Token is invalid or has expired'), 400)
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined
    await user.save();

    createSendToken(user, 200, res)
})

exports.updatePassword = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).select('+password');

    if (!(await user.correctPassword(req.body.passwordConfirm, user.password))) {
        return next(new AppError("Your current Password is wrong"), 401);   
    }

    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();
    
    createSendToken(user, 200, res)
})
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError')

const filteredObj = (obj, ...allowedFields) => {
  const newObj = {}
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el]
  })

  return newObj
}

exports.getAllUsers = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};

exports.updateMe = catchAsync(async (req, res, next) => {
  if (req,body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates. please use updatemyPassword'), 400) 
  }

  const filteredBody = filteredObj(req.body, 'name', 'email')
  const updateUser = await User.findByIdAndUpdate(req.use.id, filteredBody, {
    new: true,
    runValidators: true
  })

  res.status(200).json({
    status: "success",
    data: {
      user: updateUser
    }
  })
})

exports.getUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};

exports.createUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};

exports.updateUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};

exports.deleteUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};

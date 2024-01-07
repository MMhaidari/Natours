const express = require('express');
const userController = require('./../controllers/userController');
const authrController = require('./../controllers/authController');


const router = express.Router();

router.post('/signup', authrController.signup)
router.post('/login', authrController.login)

router.post('/forgotPassword', authrController.forgotPassword)
router.patch('/resetPassword/:token', authrController.resetPassword)

router.patch('/updatePassword', authrController.protect, authrController.updatePassword)

router.patch('/updateMe', authrController.protect, userController.updateMe)

router
  .route('/')
  .get(userController.getAllUsers)
  .post(userController.createUser);

router
  .route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

module.exports = router;

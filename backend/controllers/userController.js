const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// Register user

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Validaton
  if (!name || !email || !password) {
    res.status(400);
    throw new Error('Please fill in all required fiellds');
  }
  if (password?.length < 6) {
    res.status(400);
    throw new Error('password must be upto 6 characters');
  }

  // check if user email alreday exists

  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error('Email has already been registered');
  }

  // Create new user
  const user = await User.create({
    name,
    email,
    password,
  });

  // GEnerate Toekn

  const token = generateToken(user._id);

  // Send HTTP-only cookie

  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //1 day
    sameSite: 'none',
    secure: true,
  });

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});

// Login User

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400);
    throw new Error('Please add email and password');
  }

  // check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    res.status(400);
    throw new Error('User not found, please signup first');
  }

  // user exists, check if password is correct

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  // GEnerate Toekn

  const token = generateToken(user._id);

  // Send HTTP-only cookie

  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //1 day
    sameSite: 'none',
    secure: true,
  });

  if (user && passwordIsCorrect) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid email or password');
  }
});

module.exports = {
  registerUser,
  loginUser,
};

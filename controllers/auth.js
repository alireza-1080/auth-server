import userModel from '../models/user.js';
import firstNameValidator from '../validators/firstNameValidator.js';
import lastNameValidator from '../validators/lastNameValidator.js';
import usernameValidator from '../validators/usernameValidator.js';
import emailValidator from '../validators/emailValidator.js';
import passwordValidator from '../validators/passwordValidator.js';
import roleValidator from '../validators/roleValidator.js';
import hashFunction from '../utils/hashFunction.js';
import tokenGenerator from '../utils/tokenGenerator.js';
import comparePasswords from '../utils/comparePasswords.js';
import verifyToken from '../utils/verifyToken.js';

const signUp = async (req, res) => {
  try {
    //! Get firstName, lastName, username, email, password from req.body
    let { firstName, lastName, username, email, password } = req.body;

    //^ Validate firstName
    const firstNameValidation = firstNameValidator.validate({ firstName });

    //^ Throw an error if firstName is invalid
    if (firstNameValidation.error) {
      const errorMessage = firstNameValidation.error.details[0].message
        .replace(/\"firstName\"/g, 'First name')
        .replace(/\"/g, '');
      throw new Error(errorMessage);
    }

    //^ Capitalize the first letter of firstName and the rest of the letters should be in lowercase
    firstName =
      firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();

    //? Validate lastName
    const lastNameValidation = lastNameValidator.validate({ lastName });

    //? Throw an error if lastName is invalid
    if (lastNameValidation.error) {
      const errorMessage = lastNameValidation.error.details[0].message
        .replace(/\"lastName\"/g, 'Last name')
        .replace(/\"/g, '');
      throw new Error(errorMessage);
    }

    //? Capitalize the first letter of lastName and the rest of the letters should be in lowercase
    lastName =
      lastName?.charAt(0).toUpperCase() + lastName?.slice(1).toLowerCase();

    //^ Validate username
    const usernameValidation = usernameValidator.validate({ username });

    //^ Throw an error if username is invalid
    if (usernameValidation.error) {
      const errorMessage = usernameValidation.error.details[0].message
        .replace(/\"username\"/g, 'Username')
        .replace(/\"/g, '');
      throw new Error(errorMessage);
    }

    //^ Convert username to lowercase
    username = username.toLowerCase();

    //! Validate email
    const emailValidation = emailValidator.validate({ email });

    //! Throw an error if email is invalid
    if (emailValidation.error) {
      const errorMessage = emailValidation.error.details[0].message
        .replace(/\"email\"/g, 'Email')
        .replace(/\"/g, '');
      throw new Error(errorMessage);
    }

    //! Convert email to lowercase
    email = email.toLowerCase();

    //? Validate password
    const passwordValidation = passwordValidator.validate({ password });

    //? Throw an error if password is invalid
    if (passwordValidation.error) {
      const errorMessage = passwordValidation.error.details[0].message
        .replace(/\"password\"/g, 'Password')
        .replace(/\"/g, '');
      throw new Error(errorMessage);
    }

    //? Hash the password
    password = await hashFunction(password);

    //* check if this is the first user to sign up
    const users = await userModel.find();

    //* If this is the first user to sign up, set the role to 'admin'
    const role = users.length === 0 ? 'ADMIN' : 'USER';

    //^ Create a new user
    const newUser = new userModel({
      firstName,
      lastName,
      username,
      email,
      password,
      role,
    });

    //^ Save the new user to the database
    await newUser.save();

    //! Generate a token
    const token = tokenGenerator({ username });

    //! Send the token in the response header
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      path: '/',
    });

    //^ Send a response
    res.json({ message: 'User signed up successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const logIn = async (req, res) => {
  try {
    //? Get identifier and password from req.body
    let { identifier, password } = req.body;

    //* Convert identifier to lowercase
    identifier = identifier.toLowerCase();

    //! Check if identifier is provided
    if (!identifier) {
      throw new Error('Email or username is required');
    }

    //* Check if password is provided
    if (!password) {
      throw new Error('Password is required');
    }

    //^ Check if there is a user with the email or username
    const user = await userModel.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });

    //^ Throw an error if there is no user with the email or username
    if (!user) {
      throw new Error('User not found');
    }

    //? Compare the password
    const isMatch = await comparePasswords(password, user.password);

    //? Throw an error if the password is incorrect
    if (!isMatch) {
      throw new Error('Incorrect password');
    }

    //! Generate a token
    const token = tokenGenerator({ username: user.username });

    //! Send the token in the response header
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      path: '/',
    });

    //^ Send a response
    res.json({ message: 'User logged in successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const getMe = async (req, res) => {
  try {
    //? Get username from req body
    const { username } = req.body;

    //^ Find the user by username
    const user = await userModel
      .findOne({ username })
      .select({ password: 0, __v: 0, createdAt: 0, updatedAt: 0 });

    //^ Send the user in the response
    res.json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const logOut = async (req, res) => {
  try {
    //! Clear the token
    res.clearCookie('token');

    //^ Send a response
    res.json({ message: 'User logged out successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const verify = async (req, res) => {
  try {
    //? Get token from headers authorization
    const token = req.headers.authorization.split(' ')[1];

    //* If there is no token, throw an error
    if (!token) {
      throw new Error('Access denied');
    }

    //! Verify the token
    const verifyTokenResult = await verifyToken(token);

    res.json(verifyTokenResult);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export { signUp, logIn, getMe, logOut, verify };

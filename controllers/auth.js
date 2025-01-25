import userModel from '../models/user.js';
import firstNameValidator from '../validators/firstNameValidator.js';
import lastNameValidator from '../validators/lastNameValidator.js';
import usernameValidator from '../validators/usernameValidator.js';
import emailValidator from '../validators/emailValidator.js';
import passwordValidator from '../validators/passwordValidator.js';
import roleValidator from '../validators/roleValidator.js';
import hashFunction from '../utils/hashFunction.js';
import tokenGenerator from '../utils/tokenGenerator.js';

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
    const role = users.length === 0 ? 'admin' : 'user';

    //! Generate a token
    const token = tokenGenerator({ email, role });

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

    //^ Send a response
    res.json({ message: 'User signed up successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const logIn = async (req, res) => {
  res.json('logIn');
};

const getMe = async (req, res) => {
  res.json('getMe');
};

const logOut = async (req, res) => {
  res.json('logOut');
};

export { signUp, logIn, getMe, logOut };

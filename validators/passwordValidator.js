import joi from 'joi';

const passwordValidator = joi.object({
  password: joi.string().min(6).max(50).required().messages({
    'string.base': `"password" should be a type of 'text'`,
    'string.empty': `"password" cannot be an empty field`,
    'string.min': `"password" should have a minimum length of {#limit}`,
    'string.max': `"password" should have a maximum length of {#limit}`,
    'any.required': `"password" is a required field`,
  }),
});

export default passwordValidator;
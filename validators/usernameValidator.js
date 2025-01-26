import joi from 'joi';

const usernameValidator = joi.object({
    username: joi
        .string()
        .alphanum()
        .min(2)
        .max(50)
        .required()
        .messages({
            'string.base': `"username" should be a type of 'text'`,
            'string.empty': `"username" cannot be an empty field`,
            'string.min': `"username" should have a minimum length of {#limit}`,
            'string.max': `"username" should have a maximum length of {#limit}`,
            'string.alphanum': `"username" should only contain alphanumeric characters`,
            'any.required': `"username" is a required field`
        }),
});

export default usernameValidator;
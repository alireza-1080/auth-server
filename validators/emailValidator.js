import joi from 'joi';

const emailValidator = joi.object({
    email: joi
        .string()
        .email({ tlds: { allow: false } })
        .required()
        .lowercase()
        .messages({
            'string.base': 'Email should be a type of text',
            'string.email': 'Email must be a valid email',
            'any.required': 'Email is a required field'
        }),
});

export default emailValidator;
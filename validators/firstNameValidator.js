import joi from 'joi';

const firstNameValidator = joi.object({
    firstName: joi
        .string()
        .min(2)
        .max(50)
        .required()
        .messages({
            'string.base': `"firstName" should be a type of 'text'`,
            'string.empty': `"firstName" cannot be an empty field`,
            'string.min': `"firstName" should have a minimum length of {#limit}`,
            'string.max': `"firstName" should have a maximum length of {#limit}`,
            'any.required': `"firstName" is a required field`
        }),
});

export default firstNameValidator;
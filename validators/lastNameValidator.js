import joi from "joi";

const lastNameValidator = joi.object({
  lastName: joi.string().min(2).max(50).required().messages({
    "string.base": `"lastName" should be a type of 'text'`,
    "string.empty": `"lastName" cannot be an empty field`,
    "string.min": `"lastName" should have a minimum length of {#limit}`,
    "string.max": `"lastName" should have a maximum length of {#limit}`,
    "any.required": `"lastName" is a required field`,
  }),
});

export default lastNameValidator;
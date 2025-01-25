import joi from 'joi';

const roleValidator = joi.object({
  role: joi.string().valid('admin', 'user').required(),
});

export default roleValidator;
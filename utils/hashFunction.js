import bcrpyt from 'bcrypt';

const hashFunction = async (password) => {
  const salt = await bcrpyt.genSalt(12);
  const hashedPassword = await bcrpyt.hash(password, salt);
  return hashedPassword;
};

export default hashFunction;
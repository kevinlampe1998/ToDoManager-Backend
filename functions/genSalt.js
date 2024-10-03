import bcrypt from 'bcrypt';

const createSalt = async () => {
    const salt = await bcrypt.genSalt(10);

    console.log(salt);
};

createSalt();
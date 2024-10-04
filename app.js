import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';

import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

import User from './models/user.js';
import ToDo from './models/todo.js';

dotenv.config();

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('DB connected!'))
  .catch((err) => console.log('Error connecting DB: ', err));

const app = express();

// app.set('trust proxy', true);

app.use(cors({
  origin: ['https://to-do-manager.lampe-kevin.com', 'http://localhost:5173'],
  // origin: 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => res.send('Hello from ToDoManager Backend'))

app.post('/users-register', async (req, res) => {

  const { username, password } = req.body;

  const existsAlready = await User.findOne({ username });

  if (existsAlready) { res.json({ message:
    'Username exists already!' }); return };

  const salt = process.env.SALT;

  const hash = await bcrypt.hash(password, salt);

  const newUser = new User({ username, hash });

  const savedUser = await newUser.save();

  res.json({ message: 'User is successful registered!!', savedUser: {
    username: savedUser.username,
    _id: savedUser._id
  } });

});

app.post('/users-login', async (req, res) => {
  const { username, password } = req.body;

  const searchedUser = await User.findOne({ username });

  !searchedUser && res.json({ message: 'User not found!'});
  if (!searchedUser) return;

  const bcryptCompare = await bcrypt.compare(password, searchedUser.hash);

  if (!bcryptCompare) {
    res.json({ message: 'Password wrong!' });
    return;
  };

    const cookieData = {
      username,
      hash: searchedUser.hash
    };

    console.log('cookieData', cookieData);

    const token = jwt.sign(cookieData, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    console.log('jwt-token', token);

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 3_600_000,
      secure: true,
      // secure: false,
      sameSite: 'None',
      domain: 'to-do-manager.lampe-kevin.com',
      path: '/'
    });

    res.json({ message: 'User logged in!', searchedUser });
});

app.post('/token', async (req, res) => {

  console.log('req.cookies', req.cookies);
  console.log('req.cookies.token', req.cookies.token);

  if (!req.cookies.token) res.send({
    message: 'No access token!'
  });

  if (!req.cookies.token) return;

  const jwtVerify = jwt.verify(req.cookies.token, process.env.JWT_SECRET);

  const foundUser = await User.findOne({ username: jwtVerify.username });

  jwtVerify && foundUser && 
    res.json({ message: 'Token correct!',
      searchedUser: {
        username: foundUser.username,
        _id: foundUser._id
      }
     });
});

app.post('/to-dos', async (req, res) => {
  const newToDo = new ToDo(req.body);

  await newToDo.save();

  res.json({ message: 'New ToDo successful saved!' });
});

app.get('/to-dos/:userId', async (req, res) => {
  const toDos = await ToDo.find({ user_id: req.params.userId });

  res.json({ message: 'Got your to dos from the db', toDos });
});

app.put('/to-dos/:id', async (req, res) => {

  const changedToDo = await ToDo.updateOne({ _id: req.params.id }, req.body);

  res.json({ message: 'ToDo successful updated' });
});

app.delete('/to-dos', async (req, res) => {
  const deletedToDo =
    await ToDo.deleteOne({ _id: req.body.toDoId });
  
  res.json({ message: 'ToDo successful deleted!' });
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'User successful logged out!' });
});

app.listen(process.env.PORT, () => {
  console.log(`Server is running on http://localhost:${process.env.PORT}`);
});

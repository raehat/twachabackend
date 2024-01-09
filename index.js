const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();
const port = 3000;

// MongoDB configuration
const username = 'raehat';
const password = 'raehat';
const clusterName = 'cluster0';
const dbName = 'skinkmmapp';

const mongoURI = `mongodb+srv://raehat:raehat@cluster0.s1sqi.mongodb.net/?retryWrites=true&w=majority`;

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error.message);
  });

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'axbotaxelar@gmail.com',
    pass: 'ihrlocznakgzgtbd'
  }
});

// Mongoose schemas and models for unverified_users and verified_users collections
const unverifiedUserSchema = new mongoose.Schema({
  email: String,
  password: String,
  otp: String,
  // Add other fields as needed
});

const verifiedUserSchema = new mongoose.Schema({
  email: String,
  password: String,
  // Add other fields as needed
});

const UnverifiedUser = mongoose.model('UnverifiedUser', unverifiedUserSchema);
const VerifiedUser = mongoose.model('VerifiedUser', verifiedUserSchema);

function sendOtpEmail(email, otp) {
  const mailOptions = {
    from: 'axbotaxelar@gmail.com',
    to: email,
    subject: 'Verification Code for Signup',
    text: `Your verification code is: ${otp}`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
}

// Generate a random OTP
function generateOtp() {
  return Math.floor(Math.random() * 10000).toString().padStart(4, '0');
}

app.use(bodyParser.json());

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }

  try {
    // Check if the user already exists in the unverified_users or verified_users collection
    const existingUnverifiedUser = await UnverifiedUser.findOne({ email });
    const existingVerifiedUser = await VerifiedUser.findOne({ email });

    if (existingVerifiedUser) {
      return res.status(400).json({ error: 'Email already exists. Please choose a different email.' });
    }
    if (existingUnverifiedUser) {
      existingUnverifiedUser.deleteOne()
    }

    const otp = generateOtp();

    // Create a new user in the unverified_users collection
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUnverifiedUser = new UnverifiedUser({ email, password: hashedPassword, otp });
    await newUnverifiedUser.save();

    // Send OTP email
    sendOtpEmail(email, otp);

    return res.json({ message: 'Verification code sent to your email. Please complete the signup.' });
  } catch (error) {
    console.error('Error in signup:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/verify_otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }

  try {
    // Find the user in the unverified_users collection
    const unverifiedUser = await UnverifiedUser.findOne({ email, otp });

    if (unverifiedUser) {
      // Move the user to the verified_users collection
      const { email, password } = unverifiedUser;
      const newVerifiedUser = new VerifiedUser({ email, password: password });
      await newVerifiedUser.save();

      // Remove the user from the unverified_users collection
      await unverifiedUser.deleteOne()

      return res.json({ message: 'User verified successfully.' });
    } else {
      return res.status(401).json({ error: 'Invalid OTP. Please try again.' });
    }
  } catch (error) {
    console.error('Error in verify_otp:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
}); 

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }

  const user = await VerifiedUser.findOne({ email });

  if (user) {
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ error: 'Invalid email or password. Please try again.' });
      }

      const token = jwt.sign({ email: user.email }, 'your_jwt_secret_key', { expiresIn: '10000h' });
      return res.json({ access_token: token });
    });
  } else {
    return res.status(401).json({ error: 'Invalid email or password. Please try again.' });
  }
});

app.post('/forgot_password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }

  try {
    // Check if a verified user with this email exists
    const existingVerifiedUser = await VerifiedUser.findOne({ email });

    if (!existingVerifiedUser) {
      return res.status(404).json({ error: 'User with this email does not exist.' });
    }

    // Generate and store OTP as UnverifiedUser
    const otp = generateOtp();
    const newUnverifiedUser = new UnverifiedUser({ email, otp });
    await newUnverifiedUser.save();

    // Send OTP email
    sendOtpEmail(email, otp);

    return res.json({ message: 'OTP sent to your email. Please proceed to verify.' });
  } catch (error) {
    console.error('Error in forgot_password:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/verify_otp_forgot_password', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }

  try {
    // Find the user in the unverified_users collection
    const unverifiedUser = await UnverifiedUser.findOne({ email, otp });

    if (unverifiedUser) {
      return res.json({ message: 'OTP verified successfully. Proceed to update password.' });
    } else {
      return res.status(401).json({ error: 'Invalid OTP. Please try again.' });
    }
  } catch (error) {
    console.error('Error in verify_otp_forgot_password:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/update_password', async (req, res) => {
  const { email, password, otp } = req.body;

  if (!email || !password || !otp) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }

  try {
    // Check if for that email in unverified users, the OTP is correct
    const unverifiedUser = await UnverifiedUser.findOne({ email, otp });

    if (unverifiedUser) {
      // In VERIFIED USERS, update password with the password sent in json
      const hashedPassword = await bcrypt.hash(password, 10);
      await VerifiedUser.updateOne({ email }, { $set: { password: hashedPassword } });

      // Remove the user from the unverified_users collection
      await unverifiedUser.deleteOne();

      return res.json({ message: 'Password updated successfully.' });
    } else {
      return res.status(401).json({ error: 'Invalid OTP. Password update failed.' });
    }
  } catch (error) {
    console.error('Error in update_password:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/protected', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];

  jwt.verify(token, 'your_jwt_secret_key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    return res.json({ logged_in_as: decoded.email });
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

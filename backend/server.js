const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// Mock DB
let users = [
  { email: 'user@example.com', passwordHash: '', resetToken: null, resetTokenExpiry: null }
];

// 1️⃣ Forgot Password - generate token & send email
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ message: 'User not found' });

  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = crypto.createHash('sha256').update(token).digest('hex'); // hash token
  user.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 mins

  // Here you'd send an email. For demo, we just log the link:
  console.log(`Reset link: http://localhost:5001/reset-password/${token}`);

  res.json({ message: 'Password reset link sent' });
});

// 2️⃣ Reset Password - verify token & update password
app.post('/reset-password/:token', async (req, res) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = users.find(
    u => u.resetToken === hashedToken && u.resetTokenExpiry > Date.now()
  );
  if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

  const newHash = await bcrypt.hash(req.body.password, 10);
  user.passwordHash = newHash;
  user.resetToken = null;
  user.resetTokenExpiry = null;

  res.json({ message: 'Password has been reset' });
});

app.listen(5001, () => console.log('Server running on port 5001'));
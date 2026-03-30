const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET;

// Gmail транспорт
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// ===== РЕГИСТРАЦИЯ — Шаг 1 =====
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .or(`email.eq.${email},username.eq.${username}`)
    .single();

  if (existing) {
    return res.status(400).json({ error: 'Email or username already taken' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await supabase.from('verification_codes').delete().eq('email', email);

  await supabase.from('verification_codes').insert({
    email,
    code,
    expires_at: expiresAt
  });

  await transporter.sendMail({
    from: `"LimitlessAI" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: 'Your verification code — LimitlessAI',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#1c1a18;color:#f0ece4;border-radius:12px">
        <h1 style="font-size:24px;margin-bottom:8px;color:#f0ece4">LimitlessAI</h1>
        <p style="color:#a09890;margin-bottom:24px">Your verification code:</p>
        <div style="font-size:40px;font-weight:700;letter-spacing:8px;text-align:center;padding:24px;background:#222018;border-radius:8px;margin-bottom:24px;color:#e0563a">${code}</div>
        <p style="color:#6a6460;font-size:14px">This code expires in 10 minutes. If you did not request this, ignore this email.</p>
      </div>
    `
  });

  res.json({ success: true, message: 'Verification code sent' });
});

// ===== РЕГИСТРАЦИЯ — Шаг 2 =====
app.post('/api/verify', async (req, res) => {
  const { username, email, password, code } = req.body;

  const { data: record } = await supabase
    .from('verification_codes')
    .select('*')
    .eq('email', email)
    .eq('code', code)
    .single();

  if (!record) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  if (new Date(record.expires_at) < new Date()) {
    return res.status(400).json({ error: 'Code expired, request a new one' });
  }

  const password_hash = await bcrypt.hash(password, 12);

  const { data: user, error } = await supabase
    .from('users')
    .insert({ username, email, password_hash, verified: true })
    .select()
    .single();

  if (error) {
    return res.status(400).json({ error: 'Failed to create account' });
  }

  await supabase.from('verification_codes').delete().eq('email', email);

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ success: true, token, username: user.username });
});

// ===== ЛОГИН =====
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (!user) {
    return res.status(400).json({ error: 'Invalid email or password' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(400).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ success: true, token, username: user.username });
});

// ===== MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ===== ПЕРСОНАЖИ =====
app.get('/api/characters', async (req, res) => {
  const { search, tag } = req.query;

  let query = supabase.from('characters').select(`
    *,
    images ( id, url ),
    comments ( id )
  `);

  if (search) {
    query = query.ilike('name', `%${search}%`);
  }

  const { data, error } = await query.order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  let result = data;
  if (tag) {
    result = data.filter(c => c.tags.includes(tag));
  }

  res.json(result);
});

// ===== КОММЕНТАРИИ — получить =====
app.get('/api/comments/:characterId', async (req, res) => {
  const { data, error } = await supabase
    .from('comments')
    .select('*, users(username)')
    .eq('character_id', req.params.characterId)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ===== КОММЕНТАРИИ — добавить =====
app.post('/api/comments', authMiddleware, async (req, res) => {
  const { character_id, text } = req.body;

  if (!text?.trim()) {
    return res.status(400).json({ error: 'Comment cannot be empty' });
  }

  const { data, error } = await supabase
    .from('comments')
    .insert({
      character_id,
      user_id: req.user.userId,
      text: text.trim()
    })
    .select('*, users(username)')
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

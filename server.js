const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET;

// ===== РЕГИСТРАЦИЯ — сразу без кода =====
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .or(`email.eq.${email},username.eq.${username}`)
      .single();

    if (existing) {
      return res.status(400).json({ error: 'Email or username already taken' });
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

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ success: true, token, username: user.username });
  } catch(err) {
    console.error('Register error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ЛОГИН =====
app.post('/api/login', async (req, res) => {
  try {
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
  } catch(err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
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
  try {
    const { search, tag } = req.query;

    let query = supabase.from('characters').select(`
      *, images ( id, url ), comments ( id )
    `);

    if (search) query = query.ilike('name', `%${search}%`);

    const { data, error } = await query.order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });

    let result = data;
    if (tag) result = data.filter(c => c.tags.includes(tag));

    res.json(result);
  } catch(err) {
    console.error('Characters error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== КОММЕНТАРИИ — получить =====
app.get('/api/comments/:characterId', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('comments')
      .select('*, users(username)')
      .eq('character_id', req.params.characterId)
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== КОММЕНТАРИИ — добавить =====
app.post('/api/comments', authMiddleware, async (req, res) => {
  try {
    const { character_id, text } = req.body;

    if (!text?.trim()) {
      return res.status(400).json({ error: 'Comment cannot be empty' });
    }

    const { data, error } = await supabase
      .from('comments')
      .insert({ character_id, user_id: req.user.userId, text: text.trim() })
      .select('*, users(username)')
      .single();

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

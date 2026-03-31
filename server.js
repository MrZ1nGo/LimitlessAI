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

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ===== REGISTER =====
app.post('/api/register', async (req, res) => {
  try {
    let { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
    username = username.trim(); email = email.trim().toLowerCase();
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const { data: existing } = await supabase.from('users').select('id').or(`email.eq.${email},username.eq.${username}`).maybeSingle();
    if (existing) return res.status(400).json({ error: 'Email or username already taken' });
    const password_hash = await bcrypt.hash(password, 12);
    const { data: user, error } = await supabase.from('users').insert({ username, email, password_hash, verified: true }).select().single();
    if (error) return res.status(400).json({ error: error.message });
    const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, username: user.username, isAdmin: user.is_admin });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== LOGIN =====
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'All fields required' });
    const input = email.trim().toLowerCase();
    const { data: user } = await supabase.from('users').select('*').or(`email.eq.${input},username.ilike.${input}`).maybeSingle();
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, username: user.username, isAdmin: user.is_admin });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS GET =====
app.get('/api/characters', async (req, res) => {
  try {
    const { search, tag, sort } = req.query;
    let query = supabase.from('characters').select('*, images ( id, url ), comments ( id )');
    if (search) query = query.ilike('name', `%${search}%`);
    const orderBy = sort === 'views' ? 'views' : 'created_at';
    const { data, error } = await query.order(orderBy, { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    let result = data;
    if (tag) result = data.filter(c => c.tags?.includes(tag));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS CREATE =====
app.post('/api/characters', adminMiddleware, async (req, res) => {
  try {
    const { name, tags, jai_url, emoji } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const { data, error } = await supabase.from('characters').insert({ name, tags: tags || [], jai_url: jai_url || '', emoji: emoji || '🌸' }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS UPDATE =====
app.patch('/api/characters/:id', adminMiddleware, async (req, res) => {
  try {
    const { name, tags } = req.body;
    const { data, error } = await supabase.from('characters').update({ name, tags }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS DELETE =====
app.delete('/api/characters/:id', adminMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('characters').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS VIEW =====
app.post('/api/characters/:id/view', async (req, res) => {
  try {
    await supabase.rpc('increment_views', { char_id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== IMAGES ADD =====
app.post('/api/images', adminMiddleware, async (req, res) => {
  try {
    const { character_id, url } = req.body;
    if (!character_id || !url) return res.status(400).json({ error: 'character_id and url required' });
    const { data, error } = await supabase.from('images').insert({ character_id, url }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== IMAGES DELETE =====
app.delete('/api/images/:id', adminMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('images').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== COMMENTS GET =====
app.get('/api/comments/:characterId', async (req, res) => {
  try {
    const userId = req.query.userId || null;
    const { data, error } = await supabase.from('comments')
      .select('*, users ( username, is_admin ), comment_likes ( user_id, is_author_like )')
      .eq('character_id', req.params.characterId)
      .order('is_pinned', { ascending: false })
      .order('likes_count', { ascending: false })
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    const result = data.map(c => ({
      ...c,
      likes_count: c.comment_likes?.filter(l => !l.is_author_like).length || 0,
      author_liked: c.comment_likes?.some(l => l.is_author_like) || false,
      user_liked: userId ? c.comment_likes?.some(l => l.user_id === userId && !l.is_author_like) : false,
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== COMMENTS ADD =====
app.post('/api/comments', authMiddleware, async (req, res) => {
  try {
    const { character_id, text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
    const { data, error } = await supabase.from('comments')
      .insert({ character_id, user_id: req.user.userId, text: text.trim() })
      .select('*, users ( username, is_admin ), comment_likes ( user_id, is_author_like )')
      .single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ...data, likes_count: 0, author_liked: false, user_liked: false });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== COMMENTS DELETE =====
app.delete('/api/comments/:id', adminMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('comments').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== COMMENTS PIN =====
app.patch('/api/comments/:id/pin', adminMiddleware, async (req, res) => {
  try {
    const { pinned } = req.body;
    const { data, error } = await supabase.from('comments').update({ is_pinned: pinned }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== LIKES =====
app.post('/api/comments/:id/like', authMiddleware, async (req, res) => {
  try {
    const { isAuthorLike } = req.body;
    const commentId = req.params.id;
    const userId = req.user.userId;
    if (isAuthorLike && !req.user.isAdmin) return res.status(403).json({ error: 'Only admin can use author like' });
    const { data: existing } = await supabase.from('comment_likes').select('id').eq('comment_id', commentId).eq('user_id', userId).eq('is_author_like', isAuthorLike).maybeSingle();
    if (existing) {
      await supabase.from('comment_likes').delete().eq('id', existing.id);
      res.json({ liked: false });
    } else {
      await supabase.from('comment_likes').insert({ comment_id: commentId, user_id: userId, is_author_like: isAuthorLike });
      res.json({ liked: true });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== UPCOMING GET =====
app.get('/api/upcoming', async (req, res) => {
  try {
    const { data, error } = await supabase.from('upcoming').select('*').eq('is_active', true).order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || null);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== UPCOMING CREATE =====
app.post('/api/upcoming', adminMiddleware, async (req, res) => {
  try {
    const { name, image_url } = req.body;
    await supabase.from('upcoming').update({ is_active: false }).eq('is_active', true);
    const { data, error } = await supabase.from('upcoming').insert({ name, image_url, is_active: true }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== UPCOMING DELETE =====
app.delete('/api/upcoming', adminMiddleware, async (req, res) => {
  try {
    await supabase.from('upcoming').update({ is_active: false }).eq('is_active', true);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

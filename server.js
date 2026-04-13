const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const CDN_URL = "limitlessai-images.dingobrouset.workers.dev";

function toCdnUrl(supabaseUrl) {
  return supabaseUrl.replace(process.env.SUPABASE_URL, CDN_URL);
}
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

async function checkBanned(req, res, next) {
  if (!req.user) return next();
  try {
    const { data: user } = await supabase.from('users').select('is_banned').eq('id', req.user.userId).single();
    if (user?.is_banned) return res.status(403).json({ error: 'Account banned' });
    next();
  } catch { next(); }
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
    const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ success: true, token, username: user.username, isAdmin: user.is_admin, avatar_url: user.avatar_url || null });
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
    if (user.is_banned) return res.status(403).json({ error: 'Your account has been banned.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ success: true, token, username: user.username, isAdmin: user.is_admin, avatar_url: user.avatar_url || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== GET OWN PROFILE =====
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase.from('users').select('id, username, email, avatar_url, is_admin, created_at').eq('id', req.user.userId).single();
    if (error || !user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== GET PUBLIC PROFILE BY USERNAME =====
app.get('/api/users/:username/profile', async (req, res) => {
  try {
    const { username } = req.params;
    const viewerId = req.query.viewerId || null;

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, avatar_url, is_admin, created_at')
      .ilike('username', username)
      .single();
    if (error || !user) return res.status(404).json({ error: 'User not found' });

    const { count: followersCount } = await supabase
      .from('followers')
      .select('*', { count: 'exact', head: true })
      .eq('following_id', user.id);

    const { count: followingCount } = await supabase
      .from('followers')
      .select('*', { count: 'exact', head: true })
      .eq('follower_id', user.id);

    let isFollowing = false;
    if (viewerId) {
      const { data: f } = await supabase.from('followers').select('id').eq('follower_id', viewerId).eq('following_id', user.id).maybeSingle();
      isFollowing = !!f;
    }

    const { data: chars } = await supabase
      .from('characters')
      .select('*, images(id, url), comments(id), character_likes(user_id)')
      .eq('author', user.username)
      .order('created_at', { ascending: false });

    const characters = (chars || []).map(c => ({
      ...c,
      likes_count: c.character_likes?.length || 0,
      user_liked: viewerId ? c.character_likes?.some(l => l.user_id === viewerId) : false,
    }));

    res.json({
      user: { ...user, followers_count: followersCount || 0, following_count: followingCount || 0 },
      characters,
      isFollowing
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== FOLLOW / UNFOLLOW =====
app.post('/api/users/:username/follow', authMiddleware, checkBanned, async (req, res) => {
  try {
    const { username } = req.params;
    const followerId = req.user.userId;
    const { data: target } = await supabase.from('users').select('id').ilike('username', username).single();
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.id === followerId) return res.status(400).json({ error: 'Cannot follow yourself' });
    const { data: existing } = await supabase.from('followers').select('id').eq('follower_id', followerId).eq('following_id', target.id).maybeSingle();
    if (existing) {
      await supabase.from('followers').delete().eq('id', existing.id);
      res.json({ following: false });
    } else {
      await supabase.from('followers').insert({ follower_id: followerId, following_id: target.id });
      res.json({ following: true });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== ANALYTICS =====
app.get('/api/analytics', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { data: chars } = await supabase
      .from('characters')
      .select('id, name, views, created_at, images(id), comments(id, created_at, users(username, avatar_url)), character_likes(user_id, created_at, users(username, avatar_url))')
      .eq('author', user.username)
      .order('created_at', { ascending: false });

    const totalViews = (chars || []).reduce((s, c) => s + (c.views || 0), 0);
    const totalLikes = (chars || []).reduce((s, c) => s + (c.character_likes?.length || 0), 0);
    const totalComments = (chars || []).reduce((s, c) => s + (c.comments?.length || 0), 0);

    const { data: followersList } = await supabase
      .from('followers')
      .select('created_at, users!follower_id(username, avatar_url)')
      .eq('following_id', userId)
      .order('created_at', { ascending: false });

    const recentLikes = [];
    for (const c of (chars || [])) {
      for (const like of (c.character_likes || [])) {
        recentLikes.push({ character_name: c.name, character_id: c.id, username: like.users?.username || 'Unknown', avatar_url: like.users?.avatar_url || null, created_at: like.created_at });
      }
    }
    recentLikes.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const recentComments = [];
    for (const c of (chars || [])) {
      for (const cm of (c.comments || [])) {
        recentComments.push({ character_name: c.name, character_id: c.id, username: cm.users?.username || 'Anonymous', avatar_url: cm.users?.avatar_url || null, created_at: cm.created_at });
      }
    }
    recentComments.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const charStats = (chars || []).map(c => ({
      id: c.id, name: c.name, views: c.views || 0,
      likes: c.character_likes?.length || 0,
      comments: c.comments?.length || 0,
      images: c.images?.length || 0,
      created_at: c.created_at
    }));

    res.json({
      totals: { views: totalViews, likes: totalLikes, comments: totalComments, characters: (chars || []).length, followers: (followersList || []).length },
      charStats,
      followers: (followersList || []).map(f => ({ username: f.users?.username, avatar_url: f.users?.avatar_url, followed_at: f.created_at })),
      recentLikes: recentLikes.slice(0, 50),
      recentComments: recentComments.slice(0, 50)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== UPDATE PROFILE =====
app.patch('/api/profile', authMiddleware, checkBanned, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username?.trim()) return res.status(400).json({ error: 'Username is required' });
    const trimmed = username.trim();
    if (trimmed.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (trimmed.length > 30) return res.status(400).json({ error: 'Username too long (max 30 chars)' });
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(trimmed)) return res.status(400).json({ error: 'Username can only contain letters, numbers, _ - .' });
    const { data: existing } = await supabase.from('users').select('id').eq('username', trimmed).neq('id', req.user.userId).maybeSingle();
    if (existing) return res.status(400).json({ error: 'Username already taken' });
    const { data: user, error } = await supabase.from('users').update({ username: trimmed }).eq('id', req.user.userId).select('id, username, email, avatar_url, is_admin').single();
    if (error) return res.status(500).json({ error: error.message });
    const newToken = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ success: true, user, token: newToken });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== UPLOAD AVATAR =====
app.post('/api/profile/avatar', authMiddleware, checkBanned, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ error: 'No image provided' });
    const matches = image.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
    if (!matches) return res.status(400).json({ error: 'Invalid image format' });
    const mimeType = matches[1];
    const buffer = Buffer.from(matches[2], 'base64');
    if (buffer.length > 3 * 1024 * 1024) return res.status(400).json({ error: 'Image too large (max 3MB)' });
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowed.includes(mimeType)) return res.status(400).json({ error: 'Only JPG, PNG, GIF, WEBP allowed' });
    const ext = mimeType.split('/')[1].replace('jpeg', 'jpg');
    const fileName = `avatar_${req.user.userId}_${Date.now()}.${ext}`;
    const { error: uploadError } = await supabase.storage.from('avatars').upload(fileName, buffer, { contentType: mimeType, upsert: true });
    if (uploadError) return res.status(500).json({ error: uploadError.message });
    const { data: urlData } = supabase.storage.from('avatars').getPublicUrl(fileName);
    await supabase.from('users').update({ avatar_url: toCdnUrl(urlData.publicUrl) }).eq('id', req.user.userId);
    res.json({ success: true, avatar_url: toCdnUrl(urlData.publicUrl) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== ADMIN: BAN / UNBAN USER =====
app.post('/api/admin/users/:userId/ban', adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const { ban } = req.body;
    const { data: target } = await supabase.from('users').select('is_admin, username').eq('id', userId).single();
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.is_admin) return res.status(403).json({ error: 'Cannot ban an admin' });
    await supabase.from('users').update({ is_banned: ban }).eq('id', userId);
    res.json({ success: true, banned: ban, username: target.username });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== ADMIN: LIST USERS =====
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, username, email, avatar_url, is_admin, is_banned, created_at')
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== STORAGE =====
app.get('/api/storage/images/:folderName', adminMiddleware, async (req, res) => {
  try {
    const folderName = decodeURIComponent(req.params.folderName);
    const { data, error } = await supabase.storage.from('images').list(folderName, { limit: 500, sortBy: { column: 'name', order: 'asc' } });
    if (error) return res.status(500).json({ error: error.message });
    const files = (data || []).filter(f => f.name && !f.name.endsWith('/'));
    const urls = files.map(f => {
      const { data: urlData } = supabase.storage.from('images').getPublicUrl(`${folderName}/${f.name}`);
      return { name: f.name, url: toCdnUrl(urlData.publicUrl), path: `${folderName}/${f.name}` };
    });
    res.json(urls);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/storage/sync/:characterId', adminMiddleware, async (req, res) => {
  try {
    const { characterId } = req.params;
    const { data: char, error: charError } = await supabase.from('characters').select('name').eq('id', characterId).single();
    if (charError || !char) return res.status(404).json({ error: 'Character not found' });
    const folderName = char.name;
    const { data: files, error: listError } = await supabase.storage.from('images').list(folderName, { limit: 500, sortBy: { column: 'name', order: 'asc' } });
    if (listError) return res.status(500).json({ error: `Storage error: ${listError.message}` });
    const validFiles = (files || []).filter(f => f.name && f.name.match(/\.(jpg|jpeg|png|gif|webp|avif)$/i));
    if (!validFiles.length) return res.json({ synced: 0, total: 0, skipped: 0, message: 'No image files found in folder' });
    const { data: existingImages } = await supabase.from('images').select('url').eq('character_id', characterId);
    const existingUrls = new Set((existingImages || []).map(i => i.url));
    const toInsert = [];
    for (const file of validFiles) {
      const path = `${folderName}/${file.name}`;
      const { data: urlData } = supabase.storage.from('images').getPublicUrl(path);
      if (!existingUrls.has(toCdnUrl(urlData.publicUrl))) toInsert.push({ character_id: characterId, url: toCdnUrl(urlData.publicUrl) });
    }
    if (toInsert.length > 0) {
      const { error: insertError } = await supabase.from('images').insert(toInsert);
      if (insertError) return res.status(500).json({ error: insertError.message });
    }
    res.json({ synced: toInsert.length, total: validFiles.length, skipped: validFiles.length - toInsert.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/storage/file', adminMiddleware, async (req, res) => {
  try {
    const { path } = req.body;
    if (!path) return res.status(400).json({ error: 'path required' });
    const { error } = await supabase.storage.from('images').remove([path]);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS GET =====
app.get('/api/characters', async (req, res) => {
  try {
    const { search, tag } = req.query;
    const userId = req.query.userId || null;
    let query = supabase.from('characters').select('*, images ( id, url ), comments ( id ), character_likes ( user_id )');
    if (search) query = query.ilike('name', `%${search}%`);
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    let result = data;
    if (tag) result = data.filter(c => c.tags?.includes(tag));
    const now = new Date();
    const h24 = new Date(now - 24 * 60 * 60 * 1000);
    const w7 = new Date(now - 7 * 24 * 60 * 60 * 1000);
    result = result.map(c => ({
      ...c,
      likes_count: c.character_likes?.length || 0,
      user_liked: userId ? c.character_likes?.some(l => l.user_id === userId) : false,
      is_trending_24h: new Date(c.created_at) >= h24,
      is_trending_weekly: new Date(c.created_at) >= w7,
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS CREATE =====
app.post('/api/characters', adminMiddleware, async (req, res) => {
  try {
    const { name, tags, jai_url, emoji, author } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    if (tags && tags.length > 10) return res.status(400).json({ error: 'Maximum 10 tags allowed' });
    const { data, error } = await supabase.from('characters').insert({
      name, tags: tags || [], jai_url: jai_url || '', emoji: emoji || '🌸',
      author: author || req.user.username || 'MrZ1nGo'
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CHARACTERS UPDATE =====
app.patch('/api/characters/:id', adminMiddleware, async (req, res) => {
  try {
    const { name, tags, emoji, jai_url, author } = req.body;
    if (tags && tags.length > 10) return res.status(400).json({ error: 'Maximum 10 tags allowed' });
    const { data, error } = await supabase.from('characters').update({ name, tags, emoji, jai_url, author }).eq('id', req.params.id).select().single();
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

// ===== CHARACTER LIKE =====
app.post('/api/characters/:id/like', authMiddleware, checkBanned, async (req, res) => {
  try {
    const charId = req.params.id;
    const userId = req.user.userId;
    const { data: existing } = await supabase.from('character_likes').select('id').eq('character_id', charId).eq('user_id', userId).maybeSingle();
    if (existing) {
      await supabase.from('character_likes').delete().eq('id', existing.id);
      res.json({ liked: false });
    } else {
      await supabase.from('character_likes').insert({ character_id: charId, user_id: userId });
      res.json({ liked: true });
    }
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

// ===== IMAGES DELETE BULK =====
app.post('/api/images/delete-bulk', adminMiddleware, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!ids || !ids.length) return res.status(400).json({ error: 'ids array required' });
    const { error } = await supabase.from('images').delete().in('id', ids);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, deleted: ids.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== COMMENTS GET =====
app.get('/api/comments/:characterId', async (req, res) => {
  try {
    const userId = req.query.userId || null;
    const { data, error } = await supabase.from('comments')
      .select('*, users ( username, is_admin, avatar_url ), comment_likes ( user_id, is_author_like )')
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
app.post('/api/comments', authMiddleware, checkBanned, async (req, res) => {
  try {
    const { character_id, text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
    const { data, error } = await supabase.from('comments')
      .insert({ character_id, user_id: req.user.userId, text: text.trim() })
      .select('*, users ( username, is_admin, avatar_url ), comment_likes ( user_id, is_author_like )')
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

// ===== COMMENT LIKES =====
app.post('/api/comments/:id/like', authMiddleware, checkBanned, async (req, res) => {
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
    const { name, image_url, tags } = req.body;
    await supabase.from('upcoming').update({ is_active: false }).eq('is_active', true);
    const { data, error } = await supabase.from('upcoming').insert({ name, image_url, tags: tags || [], is_active: true }).select().single();
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

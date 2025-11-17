import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
app.use(express.json());

// 🚨 CONFIGURATION VULNÉRABLE
const JWT_SECRET = 'weaksecret'; // Secret faible
const users = []; // Base de données en mémoire

// 📌 Endpoint de test simple
app.get('/', (req, res) => {
  res.json({
    message: 'Bienvenue sur le serveur de test de vulnérabilités JWT.',
    endpoints: ['/register', '/login', '/profile', '/admin', '/verify', '/scan-token'],
  });
});

// 🚨 VULNÉRABILITÉ 1: Enregistrement sans validation correcte
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: 'Utilisateur déjà existant' });
  }

  // ⚠️ BCrypt avec salt faible
  const hashedPassword = bcrypt.hashSync(password || '', 4);
  users.push({
    id: users.length + 1,
    username,
    email,
    password: hashedPassword,
    role: 'user',
  });

  res.json({ message: 'Utilisateur créé', username });
});

// 🚨 VULNÉRABILITÉ 2: Login avec JWT non sécurisé
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password || '', user.password)) {
    return res.status(401).json({ message: 'Identifiants incorrects' });
  }

  // ⚠️ JWT sans expiration et contenant des données sensibles
  const token = jwt.sign(
    {
      userId: user.id,
      username: user.username,
      role: user.role,
      password: user.password, // ❌ Sensible
    },
    JWT_SECRET,
    { algorithm: 'HS256' }
  );

  res.json({ message: 'Connexion réussie', token });
});

// 🚨 VULNÉRABILITÉ 3: Endpoint profil sans vérification de signature
app.get('/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    // ⚠️ Décodage sans vérification
    const decoded = jwt.decode(token);
    res.json({ message: 'Profil utilisateur', decoded });
  } catch {
    res.status(401).json({ message: 'Token invalide' });
  }
});

// 🚨 VULNÉRABILITÉ 4: Admin accessible via rôle dans le token non vérifié
app.get('/admin', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const decoded = jwt.decode(token);

  if (decoded?.role === 'admin') {
    res.json({
      message: 'Accès admin autorisé',
      secrets: ['clé API : 123456', 'serveur : 10.0.0.1'],
    });
  } else {
    res.status(403).json({ message: 'Accès refusé, rôle admin requis' });
  }
});

// 🚨 VULNÉRABILITÉ 5: Vérification qui accepte algorithme "none"
app.post('/verify', (req, res) => {
  const { token } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, decoded, algorithm: 'HS256' });
  } catch {
    try {
      const decoded = jwt.verify(token, '', { algorithms: ['none'] });
      res.json({ valid: true, decoded, algorithm: 'none' });
    } catch (error) {
      res.status(400).json({ valid: false, error: error.message });
    }
  }
});

// 🔍 Scanner de vulnérabilités de JWT
app.post('/scan-token', (req, res) => {
  const { token } = req.body;
  const findings = [];

  try {
    const parts = token.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

    if (header.alg === 'none') findings.push('🔴 Algorithme "none" utilisé');
    if (!payload.exp) findings.push('⚠️ Pas de timestamp d’expiration');
    if (payload.password) findings.push('⚠️ Données sensibles incluses dans le token');

    try {
      jwt.verify(token, JWT_SECRET);
    } catch {
      findings.push('❌ Signature non vérifiée avec le secret');
    }

    res.json({ header, payload, findings });
  } catch {
    res.json({ message: 'Token invalide ou malformé' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'up', user_count: users.length });
});

// Port d’écoute
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`🚨 APPLI JWT vulnérable démarrée sur http://localhost:${PORT}`);
});

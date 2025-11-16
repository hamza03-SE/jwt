import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

// ⚠️ CONFIGURATION VULNÉRABLE ⚠️
const JWT_SECRET = 'secret123'; // Secret trop simple!
const users = [
  { id: 1, username: 'alice', password: 'pass123', role: 'user' },
  { id: 2, username: 'admin', password: 'admin123', role: 'admin' }
];

// 🚨 ROUTE 1: Login vulnérable
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    // ⚠️ VULNÉRABILITÉ: Pas d'expiration + données sensibles
    const token = jwt.sign(
      { 
        userId: user.id,
        username: user.username,
        role: user.role,
        email: user.username + '@company.com', // Donnée sensible
        password: user.password // ⚠️ MOT DE PASSE DANS JWT!
      }, 
      JWT_SECRET,
      { algorithm: 'HS256' }
      // ❌ PAS de expiresIn!
    );
    
    res.json({ 
      message: 'Bienvenue ' + user.username + '!', 
      token: token,
      role: user.role
    });
  } else {
    res.status(401).json({ message: 'Accès refusé' });
  }
});

// 🚨 ROUTE 2: Profile vulnérable
app.get('/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) return res.status(401).json({ message: 'Token manquant' });
  
  try {
    // ⚠️ VULNÉRABILITÉ: decode() au lieu de verify()
    const decoded = jwt.decode(token); // ❌ Pas de vérification!
    
    res.json({ 
      message: 'Profil utilisateur',
      user: decoded,
      note: 'Ce token a seulement été décodé, pas vérifié!'
    });
  } catch (error) {
    res.status(401).json({ message: 'Token invalide' });
  }
});

// 🚨 ROUTE 3: Admin vulnérable
app.get('/admin', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) return res.status(401).json({ message: 'Token manquant' });
  
  try {
    // ⚠️ VULNÉRABILITÉ: Pas de vérification de signature
    const decoded = jwt.decode(token);
    
    if (decoded.role === 'admin') {
      res.json({ 
        message: '🚀 ACCÈS ADMIN AUTORISÉ!',
        secrets: [
          'Liste des utilisateurs: alice, admin, bob',
          'Base de données: 192.168.1.100:5432',
          'Clé API: sk-1234567890abcdef'
        ],
        user: decoded
      });
    } else {
      res.status(403).json({ 
        message: '❌ ACCÈS REFUSÉ: Droits administrateur requis',
        yourRole: decoded.role 
      });
    }
  } catch (error) {
    res.status(401).json({ message: 'Token invalide' });
  }
});

// 🚨 ROUTE 4: Vérification vulnérable
app.post('/verify', (req, res) => {
  const { token } = req.body;
  
  try {
    // ⚠️ VULNÉRABILITÉ: Accepte l'algorithme "none"
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded, algorithm: 'HS256' });
  } catch (error) {
    try {
      // ⚠️ Tente avec algorithme "none"
      const decodedNone = jwt.verify(token, '', { algorithms: ['none'] });
      res.json({ valid: true, user: decodedNone, algorithm: 'none' });
    } catch (noneError) {
      res.json({ valid: false, error: 'Token invalide' });
    }
  }
});

app.listen(3000, () => {
  console.log('🎯 Application vulnérable démarrée: http://localhost:3000');
  console.log('📋 Endpoints:');
  console.log('   POST /login - Obtenir un token JWT');
  console.log('   GET /profile - Voir son profil');
  console.log('   GET /admin - Zone administrateur');
  console.log('   POST /verify - Vérifier un token');
});
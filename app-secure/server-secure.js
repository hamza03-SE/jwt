import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());

// === CONFIGURATION SÉCURISÉE ===
const JWT_CONFIG = {
    secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    algorithm: 'HS256',
    accessExpiresIn: '15m',    // Court pour l'accès
    refreshExpiresIn: '7d'     // Long pour le renouvellement
};

// === MIDDLEWARES DE SÉCURITÉ ===

// 1. Rate Limiting contre le brute-force
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 tentatives max par windowMs
    message: 'Trop de tentatives, réessayez plus tard'
});

// 2. Blacklist pour tokens révoqués
const tokenBlacklist = new Set();

// 3. Middleware d'authentification SÉCURISÉ
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ message: 'Token manquant' });
    }
    
    // Vérifier si le token est blacklisté
    if (tokenBlacklist.has(token)) {
        return res.status(401).json({ message: 'Token révoqué' });
    }
    
    try {
        // ✅ VÉRIFICATION SÉCURISÉE avec algorithme spécifique
        const decoded = jwt.verify(token, JWT_CONFIG.secret, { 
            algorithms: [JWT_CONFIG.algorithm], // Uniquement HS256
            maxAge: JWT_CONFIG.accessExpiresIn
        });
        
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            res.status(401).json({ message: 'Token expiré' });
        } else if (error.name === 'JsonWebTokenError') {
            res.status(401).json({ message: 'Token invalide' });
        } else {
            res.status(401).json({ message: 'Erreur d\'authentification' });
        }
    }
};

// 4. Middleware de vérification des rôles
const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ 
                message: `Accès refusé: rôle ${role} requis`,
                yourRole: req.user.role
            });
        }
        next();
    };
};

// === ROUTES SÉCURISÉES ===

// Route login avec rate limiting
app.post('/login', limiter, (req, res) => {
    const { username, password } = req.body;
    
    // Validation des entrées
    if (!username || !password) {
        return res.status(400).json({ message: 'Username et password requis' });
    }
    
    if (username.length > 50 || password.length > 100) {
        return res.status(400).json({ message: 'Données trop longues' });
    }
    
    const users = [
        { id: 1, username: 'alice', password: 'pass123', role: 'user' },
        { id: 2, username: 'admin', password: 'admin123', role: 'admin' }
    ];
    
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        // ✅ PAYLOAD SÉCURISÉ - données minimales
        const tokenPayload = {
            userId: user.id,
            username: user.username,
            role: user.role
            // ❌ PLUS de données sensibles!
        };
        
        const accessToken = jwt.sign(
            tokenPayload, 
            JWT_CONFIG.secret,
            { 
                algorithm: JWT_CONFIG.algorithm,
                expiresIn: JWT_CONFIG.accessExpiresIn
            }
        );
        
        res.json({ 
            message: 'Connexion réussie!', 
            accessToken: accessToken,
            expiresIn: JWT_CONFIG.accessExpiresIn,
            user: { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            }
        });
    } else {
        // Message générique pour éviter l'enumération
        res.status(401).json({ message: 'Identifiants incorrects' });
    }
});

// Route de déconnexion (révocation)
app.post('/logout', authenticateToken, (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    tokenBlacklist.add(token);
    res.json({ message: 'Déconnexion réussie' });
});

// Route profile sécurisée
app.get('/profile', authenticateToken, (req, res) => {
    res.json({ 
        message: 'Profil utilisateur',
        user: req.user,
        note: 'Token vérifié et validé cryptographiquement'
    });
});

// Route admin sécurisée
app.get('/admin', authenticateToken, requireRole('admin'), (req, res) => {
    res.json({ 
        message: 'Accès administrateur autorisé',
        secrets: [
            'Liste des utilisateurs: alice, admin, bob',
            'Base de données: 192.168.1.100:5432',
            'Clé API: sk-1234567890abcdef'
        ],
        user: req.user
    });
});

// ✅ Vérification SÉCURISÉE - rejette "none"
app.post('/verify', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({ error: 'Token requis' });
    }
    
    try {
        // ✅ UNIQUEMENT HS256 autorisé
        const decoded = jwt.verify(token, JWT_CONFIG.secret, { 
            algorithms: [JWT_CONFIG.algorithm] 
        });
        
        res.json({ 
            valid: true, 
            user: decoded,
            algorithm: JWT_CONFIG.algorithm
        });
    } catch (error) {
        res.status(401).json({ 
            valid: false, 
            error: 'Token invalide',
            details: error.message 
        });
    }
});

// Endpoint de santé
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        security: 'ENABLED',
        features: [
            'Rate Limiting',
            'Token Expiration', 
            'Algorithm Validation',
            'Input Sanitization'
        ]
    });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`✅ Application SÉCURISÉE démarrée: http://localhost:${PORT}`);
    console.log('🔒 Fonctionnalités de sécurité activées:');
    console.log('   ✓ Rate Limiting (5 req/15min)');
    console.log('   ✓ Token expiration (15 minutes)');
    console.log('   ✓ Algorithme HS256 uniquement');
    console.log('   ✓ Vérification cryptographique');
    console.log('   ✓ Blacklist des tokens révoqués');
});
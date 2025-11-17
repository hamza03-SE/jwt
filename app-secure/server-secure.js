import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

const app = express();
app.use(express.json());

// === CONFIGURATION SÉCURISÉE ===
const JWT_CONFIG = {
    secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    algorithm: 'HS256',
    accessExpiresIn: '15m',
    refreshExpiresIn: '7d'
};

// === MIDDLEWARES DE SÉCURITÉ ===

// 1. Helmet pour les en-têtes de sécurité
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"]
        }
    },
    xFrameOptions: { action: 'deny' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// 2. Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Trop de tentatives, réessayez plus tard' },
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Trop de requêtes, réessayez plus tard' }
});

// 3. Blacklist pour tokens révoqués
const tokenBlacklist = new Set();

// 4. Middleware d'authentification SÉCURISÉ
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ message: 'Token manquant' });
    }
    
    if (tokenBlacklist.has(token)) {
        return res.status(401).json({ message: 'Token révoqué' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_CONFIG.secret, { 
            algorithms: [JWT_CONFIG.algorithm],
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

// 5. Middleware de vérification des rôles
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

// Page d'accueil avec interface de test
app.get('/', generalLimiter, (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔐 Application JWT Sécurisée - Tests ZAP</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 40px; 
                background: #f5f5f5;
            }
            .container { 
                max-width: 1000px; 
                margin: 0 auto; 
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .section { 
                margin: 25px 0; 
                padding: 20px; 
                border: 1px solid #ddd;
                border-radius: 8px;
                background: #fafafa;
            }
            button { 
                padding: 12px 20px; 
                margin: 8px; 
                background: #007cba;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
            }
            button:hover { background: #005a87; }
            button.vulnerable { background: #dc3545; }
            button.vulnerable:hover { background: #bd2130; }
            textarea, input { 
                width: 100%; 
                padding: 10px; 
                margin: 5px 0; 
                border: 1px solid #ccc;
                border-radius: 4px;
                font-family: monospace;
            }
            .result { 
                margin: 15px 0; 
                padding: 15px; 
                border-radius: 5px;
                background: #f8f9fa;
                border-left: 4px solid #007cba;
            }
            .success { border-left-color: #28a745; background: #d4edda; }
            .error { border-left-color: #dc3545; background: #f8d7da; }
            .warning { border-left-color: #ffc107; background: #fff3cd; }
            h1 { color: #333; border-bottom: 2px solid #007cba; padding-bottom: 10px; }
            h2 { color: #555; margin-top: 0; }
            .grid { 
                display: grid; 
                grid-template-columns: 1fr 1fr; 
                gap: 20px; 
                margin: 20px 0;
            }
            .card {
                background: white;
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Application JWT Sécurisée - Tests ZAP</h1>
            <p>Cette application démontre une implémentation sécurisée de JWT avec des endpoints de test pour l'analyse de sécurité.</p>
            
            <div class="grid">
                <div class="card">
                    <h3>✅ Fonctionnalités Sécurisées</h3>
                    <ul>
                        <li>Rate Limiting (5 req/15min auth)</li>
                        <li>Tokens JWT avec expiration</li>
                        <li>Algorithme HS256 uniquement</li>
                        <li>Blacklist des tokens révoqués</li>
                        <li>Validation des rôles</li>
                        <li>En-têtes de sécurité Helmet</li>
                    </ul>
                </div>
                <div class="card">
                    <h3>🔍 Endpoints de Test ZAP</h3>
                    <ul>
                        <li><code>/login</code> - Authentification</li>
                        <li><code>/profile</code> - Données utilisateur</li>
                        <li><code>/admin</code> - Zone administrateur</li>
                        <li><code>/verify</code> - Vérification token</li>
                        <li><code>/vulnerable-data</code> - Données sensibles</li>
                    </ul>
                </div>
            </div>

            <!-- Section Login -->
            <div class="section">
                <h2>1. Authentification</h2>
                <button onclick="login('alice', 'pass123')">Login Alice (user)</button>
                <button onclick="login('admin', 'admin123')">Login Admin</button>
                <button onclick="login('', '')" class="vulnerable">Login Vide (test injection)</button>
                <div id="tokenResult" class="result"></div>
            </div>

            <!-- Section Profile -->
            <div class="section">
                <h2>2. Profil Utilisateur</h2>
                <button onclick="getProfile()">Voir Mon Profil</button>
                <button onclick="getProfileWithoutToken()" class="vulnerable">Profil Sans Token</button>
                <div id="profileResult" class="result"></div>
            </div>

            <!-- Section Admin -->
            <div class="section">
                <h2>3. Zone Admin</h2>
                <button onclick="getAdmin()">Accès Admin</button>
                <button onclick="getAdminAsUser()" class="vulnerable">Admin en tant qu'User</button>
                <div id="adminResult" class="result"></div>
            </div>

            <!-- Section Tests Sécurité -->
            <div class="section">
                <h2>4. Tests de Sécurité</h2>
                <button onclick="testVulnerableData()">Données Sensibles</button>
                <button onclick="testVerifyToken()">Vérifier Token</button>
                <button onclick="testLogout()">Déconnexion</button>
                <button onclick="testRateLimit()" class="vulnerable">Test Rate Limiting</button>
                <div id="securityResult" class="result"></div>
            </div>

            <!-- Token Display -->
            <div class="section">
                <h2>Token Actuel :</h2>
                <textarea id="currentToken" rows="3" placeholder="Aucun token..."></textarea>
                <button onclick="copyToken()">Copier Token</button>
                <button onclick="clearToken()" class="vulnerable">Effacer Token</button>
            </div>
        </div>

        <script>
            let currentToken = '';

            async function login(username, password) {
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    if (response.ok) {
                        currentToken = data.accessToken;
                        document.getElementById('currentToken').value = currentToken;
                        document.getElementById('tokenResult').innerHTML = 
                            \`<div class="success"><strong>✅ Login réussi!</strong><br>
                            Role: \${data.user.role}<br>
                            Expire dans: \${data.expiresIn}</div>\`;
                    } else {
                        document.getElementById('tokenResult').innerHTML = 
                            \`<div class="error"><strong>❌ Erreur:</strong> \${data.message}</div>\`;
                    }
                } catch (error) {
                    document.getElementById('tokenResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur réseau:</strong> \${error.message}</div>\`;
                }
            }

            async function getProfile() {
                if (!currentToken) {
                    alert('Obtenez un token d\\'abord!');
                    return;
                }

                try {
                    const response = await fetch('/profile', {
                        headers: { 'Authorization': \`Bearer \${currentToken}\` }
                    });
                    const data = await response.json();
                    document.getElementById('profileResult').innerHTML = 
                        \`<div class="success"><strong>✅ Profil récupéré</strong><br>
                        <pre>\${JSON.stringify(data, null, 2)}</pre></div>\`;
                } catch (error) {
                    document.getElementById('profileResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function getProfileWithoutToken() {
                try {
                    const response = await fetch('/profile');
                    const data = await response.json();
                    document.getElementById('profileResult').innerHTML = 
                        \`<div class="warning"><strong>⚠ Réponse sans token:</strong><br>
                        <pre>\${JSON.stringify(data, null, 2)}</pre></div>\`;
                } catch (error) {
                    document.getElementById('profileResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function getAdmin() {
                if (!currentToken) {
                    alert('Obtenez un token d\\'abord!');
                    return;
                }

                try {
                    const response = await fetch('/admin', {
                        headers: { 'Authorization': \`Bearer \${currentToken}\` }
                    });
                    const data = await response.json();
                    document.getElementById('adminResult').innerHTML = 
                        \`<div class="success"><strong>✅ Accès admin réussi</strong><br>
                        <pre>\${JSON.stringify(data, null, 2)}</pre></div>\`;
                } catch (error) {
                    document.getElementById('adminResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function getAdminAsUser() {
                // Essayer d'accéder à /admin sans token admin
                try {
                    const response = await fetch('/admin');
                    const data = await response.json();
                    document.getElementById('adminResult').innerHTML = 
                        \`<div class="warning"><strong>⚠ Réponse admin sans auth:</strong><br>
                        <pre>\${JSON.stringify(data, null, 2)}</pre></div>\`;
                } catch (error) {
                    document.getElementById('adminResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function testVulnerableData() {
                try {
                    const response = await fetch('/vulnerable-data');
                    const data = await response.json();
                    document.getElementById('securityResult').innerHTML = 
                        \`<div class="warning"><strong>🔍 Données sensibles exposées:</strong><br>
                        <pre>\${JSON.stringify(data, null, 2)}</pre></div>\`;
                } catch (error) {
                    document.getElementById('securityResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function testVerifyToken() {
                if (!currentToken) {
                    alert('Obtenez un token d\\'abord!');
                    return;
                }

                try {
                    const response = await fetch('/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: currentToken })
                    });
                    const data = await response.json();
                    document.getElementById('securityResult').innerHTML = 
                        \`<div class="success"><strong>✅ Vérification token:</strong><br>
                        <pre>\${JSON.stringify(data, null, 2)}</pre></div>\`;
                } catch (error) {
                    document.getElementById('securityResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function testLogout() {
                if (!currentToken) {
                    alert('Aucun token à révoquer!');
                    return;
                }

                try {
                    const response = await fetch('/logout', {
                        method: 'POST',
                        headers: { 'Authorization': \`Bearer \${currentToken}\` }
                    });
                    const data = await response.json();
                    document.getElementById('securityResult').innerHTML = 
                        \`<div class="success"><strong>✅ \${data.message}</strong></div>\`;
                    currentToken = '';
                    document.getElementById('currentToken').value = '';
                } catch (error) {
                    document.getElementById('securityResult').innerHTML = 
                        \`<div class="error"><strong>❌ Erreur:</strong> \${error.message}</div>\`;
                }
            }

            async function testRateLimit() {
                // Tester le rate limiting en faisant plusieurs requêtes rapides
                for (let i = 1; i <= 6; i++) {
                    setTimeout(async () => {
                        try {
                            const response = await fetch('/login', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ username: 'test', password: 'test' })
                            });
                            const data = await response.json();
                            console.log(\`Tentative \${i}: \`, data);
                        } catch (error) {
                            console.log(\`Tentative \${i} erreur: \`, error.message);
                        }
                    }, i * 500);
                }
                document.getElementById('securityResult').innerHTML = 
                    '<div class="warning"><strong>⚠ Test Rate Limiting lancé (voir console)</strong></div>';
            }

            function copyToken() {
                if (currentToken) {
                    navigator.clipboard.writeText(currentToken);
                    alert('Token copié!');
                }
            }

            function clearToken() {
                currentToken = '';
                document.getElementById('currentToken').value = '';
                document.getElementById('securityResult').innerHTML = 
                    '<div class="warning"><strong>⚠ Token effacé</strong></div>';
            }
        </script>
    </body>
    </html>
    `);
});

// Route login avec rate limiting
app.post('/login', authLimiter, (req, res) => {
    const { username, password } = req.body;
    
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
        const tokenPayload = {
            userId: user.id,
            username: user.username,
            role: user.role,
            iat: Math.floor(Date.now() / 1000)
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
        note: 'Token vérifié et validé cryptographiquement',
        timestamp: new Date().toISOString()
    });
});

// Route admin sécurisée
app.get('/admin', authenticateToken, requireRole('admin'), (req, res) => {
    res.json({ 
        message: 'Accès administrateur autorisé',
        secrets: [
            'Liste des utilisateurs: alice, admin, bob',
            'Base de données: 192.168.1.100:5432',
            'Clé API: sk-1234567890abcdef',
            'Certificats SSL: /etc/ssl/private/'
        ],
        user: req.user,
        accessTime: new Date().toISOString()
    });
});

// ✅ Vérification SÉCURISÉE - rejette "none"
app.post('/verify', generalLimiter, (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({ error: 'Token requis' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_CONFIG.secret, { 
            algorithms: [JWT_CONFIG.algorithm] 
        });
        
        res.json({ 
            valid: true, 
            user: decoded,
            algorithm: JWT_CONFIG.algorithm,
            expiresIn: JWT_CONFIG.accessExpiresIn
        });
    } catch (error) {
        res.status(401).json({ 
            valid: false, 
            error: 'Token invalide',
            details: error.message 
        });
    }
});

// Endpoint avec données potentiellement sensibles (pour tests ZAP)
app.get('/vulnerable-data', generalLimiter, (req, res) => {
    res.json({
        serverInfo: {
            framework: 'Express',
            version: '4.18.0',
            environment: process.env.NODE_ENV || 'development'
        },
        database: {
            host: '192.168.1.100',
            port: 5432,
            name: 'app_db'
        },
        apiKeys: {
            stripe: 'sk_test_1234567890abcdef',
            sendgrid: 'SG.abc123def456'
        },
        users: [
            { id: 1, email: 'admin@company.com', role: 'admin' },
            { id: 2, email: 'user@company.com', role: 'user' }
        ],
        timestamp: Math.floor(Date.now() / 1000)
    });
});

// Endpoint de santé
app.get('/health', generalLimiter, (req, res) => {
    res.json({ 
        status: 'OK', 
        security: 'ENABLED',
        timestamp: new Date().toISOString(),
        features: [
            'Rate Limiting',
            'Token Expiration', 
            'Algorithm Validation',
            'Input Sanitization',
            'CSP Headers',
            'X-Frame-Options',
            'HSTS'
        ]
    });
});

// Gestion des routes non trouvées
app.use('*', generalLimiter, (req, res) => {
    res.status(404).json({ 
        error: 'Route non trouvée',
        path: req.originalUrl,
        method: req.method
    });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`\n✅ Application SÉCURISÉE démarrée: http://localhost:${PORT}`);
    console.log('🔒 Fonctionnalités de sécurité activées:');
    console.log('   ✓ Rate Limiting (5 req/15min auth, 100 req/15min général)');
    console.log('   ✓ Token expiration (15 minutes)');
    console.log('   ✓ Algorithme HS256 uniquement');
    console.log('   ✓ Vérification cryptographique');
    console.log('   ✓ Blacklist des tokens révoqués');
    console.log('   ✓ En-têtes CSP et sécurité Helmet');
    console.log('   ✓ Validation des rôles');
    console.log('\n🔍 Points de test pour ZAP:');
    console.log('   - Injection SQL: /login avec données malformées');
    console.log('   - Broken Authentication: /profile sans token');
    console.log('   - Sensitive Data Exposure: /vulnerable-data');
    console.log('   - Rate Limiting: multiples requêtes /login');
    console.log('   - JWT Attacks: tokens modifiés sur /verify');
    console.log('\n👤 Comptes de test:');
    console.log('   User: alice / pass123');
    console.log('   Admin: admin / admin123\n');
});
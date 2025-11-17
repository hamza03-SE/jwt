🔐 Application JWT Sécurisée
📋 Table des Matières
Aperçu

Fonctionnalités de Sécurité

Installation

Configuration

Utilisation

API Endpoints

Tests de Sécurité

Tests Postman

Dépannage

Structure du Projet

🎯 Aperçu
Cette application Express.js démontre une implémentation sécurisée de JWT avec des mécanismes de protection complets contre les vulnérabilités courantes. Elle sert de référence pour les bonnes pratiques de sécurité JWT en environnement de production.

🚀 Fonctions Principales
✅ Authentification JWT sécurisée avec expiration

✅ Rate Limiting contre les attaques par brute-force

✅ Révocation des tokens via blacklist

✅ Validation stricte des rôles et permissions

✅ En-têtes de sécurité HTTP renforcés

✅ Interface web de test intégrée

👤 Comptes de Test
Utilisateur	Mot de passe	Rôle	Accès
alice	pass123	user	Profil utilisateur
admin	admin123	admin	Profil + Zone admin
🛡️ Fonctionnalités de Sécurité
Mesures Implémentées
Fonctionnalité	Protection	Configuration
Rate Limiting	Brute-force	5 req/15min (auth), 100 req/15min (général)
JWT Expiration	Token replay	15 minutes pour les tokens d'accès
Algorithm Validation	Algorithm "none" attack	HS256 uniquement autorisé
Token Blacklist	Token reuse après logout	Set en mémoire
Input Sanitization	Injection	Validation des longueurs et types
Security Headers	XSS/Clickjacking	CSP, HSTS, X-Frame-Options
Configuration JWT Sécurisée
javascript
{
  algorithm: "HS256",          // Seul algorithme autorisé
  accessExpiresIn: "15m",      // Court pour la sécurité
  secret: "crypto_random_64"   // Génération sécurisée
}
⚙️ Installation
Prérequis
Node.js 16.0 ou supérieur

npm ou yarn

Steps d'Installation
Cloner le projet

bash
git clone <repository-url>
cd app-secure
Installer les dépendances

bash
npm install
Configurer l'environnement (optionnel)

bash
# Créer un fichier .env
echo "JWT_SECRET=your_super_secure_secret_here" > .env
echo "PORT=3001" >> .env
echo "NODE_ENV=development" >> .env
Démarrer l'application

bash
# Mode développement
npm run dev

# Mode production
npm start
Vérifier le démarrage

bash
curl http://localhost:3001/health
Réponse attendue:

json
{
  "status": "OK",
  "security": "ENABLED",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "features": [
    "Rate Limiting",
    "Token Expiration",
    "Algorithm Validation",
    "Input Sanitization",
    "CSP Headers",
    "X-Frame-Options",
    "HSTS"
  ]
}
🔧 Configuration
Variables d'Environnement
Variable	Défaut	Description
JWT_SECRET	Généré aléatoirement	Secret pour signer les JWT
PORT	3001	Port d'écoute de l'application
NODE_ENV	development	Environnement d'exécution
Fichier .env Exemple
env
JWT_SECRET=your_very_secure_secret_key_here_min_32_chars
PORT=3001
NODE_ENV=production
🖥️ Utilisation
Interface Web
Accédez à l'interface de test à l'adresse:

text
http://localhost:3001
L'interface permet de:

Tester l'authentification

Vérifier les accès aux ressources

Tester les mécanismes de sécurité

Voir et copier les tokens JWT

Commandes curl
Authentification
bash
# Login utilisateur
curl -X POST http://localhost:3001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"pass123"}'

# Login administrateur  
curl -X POST http://localhost:3001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
Accès aux ressources
bash
# Récupérer le profil (remplacez <token> par un token valide)
curl -X GET http://localhost:3001/profile \
  -H "Authorization: Bearer <token>"

# Accéder à la zone admin
curl -X GET http://localhost:3001/admin \
  -H "Authorization: Bearer <admin_token>"
📡 API Endpoints
🔐 Authentification
POST /login
Authentifie un utilisateur et retourne un token JWT.

Body:

json
{
  "username": "string",
  "password": "string"
}
Réponses:

200 - Succès

json
{
  "message": "Connexion réussie!",
  "accessToken": "eyJ...",
  "expiresIn": "15m",
  "user": {
    "id": 1,
    "username": "alice", 
    "role": "user"
  }
}
400 - Données manquantes ou invalides

401 - Identifiants incorrects

429 - Trop de tentatives

POST /logout
Révoque le token JWT actuel.

Headers:

text
Authorization: Bearer <token>
Réponses:

200 - Succès

json
{
  "message": "Déconnexion réussie"
}
401 - Token invalide ou manquant

👤 Gestion Utilisateur
GET /profile
Récupère le profil de l'utilisateur authentifié.

Headers:

text
Authorization: Bearer <token>
Réponses:

200 - Succès

json
{
  "message": "Profil utilisateur",
  "user": {
    "userId": 1,
    "username": "alice",
    "role": "user",
    "iat": 1638319459
  },
  "note": "Token vérifié et validé cryptographiquement",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
401 - Token manquant, expiré ou révoqué

GET /admin
Accès aux fonctionnalités réservées aux administrateurs.

Headers:

text
Authorization: Bearer <token>
Réponses:

200 - Succès (admin uniquement)

json
{
  "message": "Accès administrateur autorisé",
  "secrets": [
    "Liste des utilisateurs: alice, admin, bob",
    "Base de données: 192.168.1.100:5432",
    "Clé API: sk-1234567890abcdef",
    "Certificats SSL: /etc/ssl/private/"
  ],
  "user": {
    "userId": 2,
    "username": "admin",
    "role": "admin",
    "iat": 1638319459
  },
  "accessTime": "2024-01-01T00:00:00.000Z"
}
401 - Token invalide

403 - Rôle admin requis

🧪 Tests de Sécurité
POST /verify
Vérifie la validité cryptographique d'un token JWT.

Body:

json
{
  "token": "string"
}
Réponses:

200 - Token valide

json
{
  "valid": true,
  "user": {
    "userId": 1,
    "username": "alice",
    "role": "user",
    "iat": 1638319459
  },
  "algorithm": "HS256",
  "expiresIn": "15m"
}
400 - Token manquant

401 - Token invalide

GET /vulnerable-data
Endpoint contenant des données sensibles pour tests de sécurité.

Réponses:

200 - Données de test

json
{
  "serverInfo": {
    "framework": "Express",
    "version": "4.18.0",
    "environment": "development"
  },
  "database": {
    "host": "192.168.1.100",
    "port": 5432,
    "name": "app_db"
  },
  "apiKeys": {
    "stripe": "sk_test_1234567890abcdef",
    "sendgrid": "SG.abc123def456"
  },
  "users": [
    {
      "id": 1,
      "email": "admin@company.com",
      "role": "admin"
    },
    {
      "id": 2, 
      "email": "user@company.com",
      "role": "user"
    }
  ],
  "timestamp": 1638319459
}
429 - Rate limit dépassé

GET /health
Statut de l'application et état des fonctionnalités de sécurité.

Réponses:

200 - Application opérationnelle

{
  "status": "OK",
  "security": "ENABLED", 
  "timestamp": "2024-01-01T00:00:00.000Z",
  "features": [
    "Rate Limiting",
    "Token Expiration",
    "Algorithm Validation", 
    "Input Sanitization",
    "CSP Headers",
    "X-Frame-Options",
    "HSTS"
  ]
}

# 🚨 JWT Vulnerable API

Cette application ExpressJS est un **serveur volontairement vulnérable aux attaques JWT**. Elle permet de tester et comprendre les failles de sécurité classiques liées à l'utilisation incorrecte des JSON Web Tokens.

> ⚠️ **Attention : Ce projet est uniquement destiné à des fins d’apprentissage. Ne jamais déployer ce code en production.**

---

## 🧩 Fonctionnalités

- Inscription d'utilisateur sans validation
- Login avec token JWT sans expiration
- Profil accessible sans vérification de signature
- Accès admin via simple injection de rôle dans le token
- Support de l'algorithme `none`
- Scanner automatisé des tokens JWT

---

## 🚨 Vulnérabilités incluses

| N°  | Endpoint      | Description de la vulnérabilité                    | Risque                                       |
|-----|---------------|----------------------------------------------------|----------------------------------------------|
| 1   | `/register`   | Pas de validation de données, hash faible          | Injection, mots de passe faibles             |
| 2   | `/login`      | JWT sans expiration, données sensibles dans le payload | Token volé valable indéfiniment              |
| 3   | `/profile`    | `jwt.decode()` sans vérification de signature      | Jeton non signé accepté                      |
| 4   | `/admin`      | Rôle déclaré dans le JWT non vérifié               | Escalade de privilèges                       |
| 5   | `/verify`     | Accepte les tokens `alg: none`                     | Bypass complet d’authentification            |
| 6   | `/scan-token` | Scanner révèle les failles mais ne les empêche pas | Diagnostic mais pas de protection            |

---

## 🚀 Installation et Exécution

### Pré-requis
- **Node.js** (version 14 ou supérieure)
- **npm**

### Installation
Clonez le dépôt et installez les dépendances :

```bash
git clone <repo-url>
cd ProjectJWT
npm install
Démarrage
bash
Copier le code
npm start
Le serveur démarre sur :
📍 http://localhost:3001

🔧 Endpoints disponibles
Route	Méthode	Description
/	GET	Page de bienvenue
/register	POST	Inscription utilisateur
/login	POST	Connexion + génération du JWT vulnérable
/profile	GET	Profil utilisateur à partir du token
/admin	GET	Ressource admin vulnérable
/verify	POST	Vérifie un token avec alg HS256 ou none
/scan-token	POST	Analyse un JWT et détecte les failles
/health	GET	Status et statistiques

📬 Tester les vulnérabilités avec Postman
Ouvre Postman et crée une nouvelle collection appelée "JWT Vulnerable API".

Ajoute les requêtes suivantes :

1. Register (vulnérable)
http
Copier le code
POST /register
Content-Type: application/json

{
    "username": "admin",
    "password": "password123",
    "email": "admin@test.com"
}
2. Login (JWT sans exp, données sensibles)

POST /login
Content-Type: application/json

{
    "username": "admin",
    "password": "password123"
}
Récupère le token retourné.

3. Profile (decode sans signature)

GET /profile
Authorization: Bearer <TOKEN>
4. Admin (bypass via rôle)
Modifie le payload du token et change role → "admin", puis envoie :


GET /admin
Authorization: Bearer <TOKEN_MODIF>
5. Verify (alg: none)
Génère un token alg: none sur https://jwt.io puis :

POST /verify
Content-Type: application/json

{
    "token": "<NONE_ALG_TOKEN>"
}
6. Scanner

POST /scan-token
Content-Type: application/json

{
    "token": "<ANY_JWT>"
}
🛡️ Pour aller plus loin
Développer une version sécurisée de ce projet

Ajouter jwt.verify avec secret + exp

Mettre en place des middlewares de validation

Stocker les tokens invalidés (blacklist)

Interdire alg: none

📚 Ressources utiles
https://jwt.io/

https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html

https://portswigger.net/web-security/jwt


💡 Ce projet peut servir d'environnement de test pour automatiser des scans avec des outils comme Postman et ZAP.





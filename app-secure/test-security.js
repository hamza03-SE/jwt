import jwt from 'jsonwebtoken';
import axios from 'axios';

const SECURE_APP = 'http://localhost:3001';

async function testSecurity() {
    console.log('🔒 TEST DE SÉCURITÉ - Application Sécurisée\n');

    try {
        // === TEST 1: Login normal ===
        console.log('1️⃣ Test de connexion normal...');
        const loginResponse = await axios.post(`${SECURE_APP}/login`, {
            username: 'alice',
            password: 'pass123'
        });
        
        const secureToken = loginResponse.data.accessToken;
        console.log('✅ Connexion réussie');
        console.log('Token sécurisé:', secureToken.substring(0, 50) + '...');
        console.log('Expiration:', loginResponse.data.expiresIn);
        console.log('');

        // === TEST 2: Vérification du token ===
        console.log('2️⃣ Analyse du token sécurisé...');
        const decoded = jwt.decode(secureToken);
        console.log('Payload:', JSON.stringify(decoded, null, 2));
        
        // Vérifier la présence d'expiration
        if (decoded.exp) {
            console.log('✅ Token a une expiration');
        } else {
            console.log('❌ Token sans expiration');
        }
        
        // Vérifier absence de données sensibles
        if (!decoded.password && !decoded.email) {
            console.log('✅ Aucune donnée sensible dans le token');
        }
        console.log('');

        // === TEST 3: Tentative d\'attaque "none" ===
        console.log('3️⃣ Test attaque algorithme "none"...');
        const noneToken = jwt.sign(
            { userId: 999, username: 'hacker', role: 'admin' },
            '',
            { algorithm: 'none' }
        );
        
        try {
            await axios.post(`${SECURE_APP}/verify`, { token: noneToken });
            console.log('❌ VULNÉRABLE: Algorithme "none" accepté');
        } catch (error) {
            console.log('✅ SÉCURISÉ: Algorithme "none" rejeté');
            console.log('   Message:', error.response?.data.error);
        }
        console.log('');

        // === TEST 4: Accès admin avec token user ===
        console.log('4️⃣ Test accès admin avec token user...');
        try {
            await axios.get(`${SECURE_APP}/admin`, {
                headers: { Authorization: `Bearer ${secureToken}` }
            });
            console.log('❌ VULNÉRABLE: Accès admin avec rôle user');
        } catch (error) {
            console.log('✅ SÉCURISÉ: Accès admin refusé pour user');
            console.log('   Message:', error.response?.data.message);
        }
        console.log('');

        // === TEST 5: Test rate limiting ===
        console.log('5️⃣ Test rate limiting...');
        const failedAttempts = [];
        for (let i = 0; i < 6; i++) {
            try {
                await axios.post(`${SECURE_APP}/login`, {
                    username: 'wronguser',
                    password: 'wrongpass'
                });
            } catch (error) {
                failedAttempts.push(error.response?.status);
            }
        }
        
        const rateLimitErrors = failedAttempts.filter(status => status === 429);
        if (rateLimitErrors.length > 0) {
            console.log('✅ SÉCURISÉ: Rate limiting activé');
        } else {
            console.log('❌ VULNÉRABLE: Rate limiting désactivé');
        }
        console.log('');

        // === TEST 6: Vérification payload modifié ===
        console.log('6️⃣ Test token modifié...');
        const userDecoded = jwt.decode(secureToken);
        userDecoded.role = 'admin'; // Tentative de modification
        
        const modifiedToken = jwt.sign(userDecoded, 'wrong_secret');
        
        try {
            await axios.get(`${SECURE_APP}/profile`, {
                headers: { Authorization: `Bearer ${modifiedToken}` }
            });
            console.log('❌ VULNÉRABLE: Token modifié accepté');
        } catch (error) {
            console.log('✅ SÉCURISÉ: Token modifié rejeté');
        }

    } catch (error) {
        console.log('❌ Erreur:', error.message);
    }
}

testSecurity();
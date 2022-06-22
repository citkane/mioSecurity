if(!process.env.NODE_ENV) process.env.NODE_ENV = "development";

const ChallengeDefs = require('./ChallengeDefs');
const bcrypt = require('bcrypt');
const jose = require('jose');
const JWT = jose.JWT;
const saltRounds = 10;

let logger, config;
module.exports = class Keygen extends ChallengeDefs {
    constructor(_logger, domain, _config) {
        super(_logger, domain, _config);
        logger = _logger;
        config = _config;
    }

    async generateDomainKeys() {

        return jose.generateKeyPair('RSA-OAEP', 2048)
        .then(async ({publicKey, privateKey}) => {
            return {
                privatePEM: await jose.exportPKCS8(privateKey),
                publicPEM: await jose.exportSPKI(publicKey)
            }
        })
        .then(async ({privatePEM, publicPEM}) => {
            return [
                await this.savePrivateKey(privatePEM),
                await this.savePublicKey(publicPEM)
            ]
        }).then(paths => {
            logger.prompt(`
Domain private key created at: ${paths[0]}
Domain public key created at: ${paths[1]}
            `, 'POC security hook point', 'cyan')
        })
        .catch((err) => {
            logger.log(err)
        })
    }

    newServiceToken(serviceName){
        const service = this.cache.service[serviceName];
        if(!service) return Promise.reject(logger.logInvalid(
            404, `Service "${serviceName}" has a public key, but is not registered.Please delete the key and register the service.`
        ));
        return this.loadDomainKeys()
        .then(
            async () => await new jose.SignJWT({})
                .setProtectedHeader({alg:'RS256'})
                .setIssuer(service)
                .setExpirationTime(config.get('tokenExpiry.service'))
                .sign(this.privateKey)
        );
    }
    newUserToken(user, expires){
        return this.loadDomainKeys()
        .then(
            async() => await new jose.SignJWT({})
                .setProtectedHeader({alg:'RS256'})
                .setIssuer(user)
                .setExpirationTime(expires || config.get('tokenExpiry.user'))
                .sign(this.privateKey)
        );
    }
    hashPassword(password){
        return new Promise((resolve, reject) => {
            bcrypt.hash(password, saltRounds, (err, hash) => {
                if(err) reject(logger.logInvalid(500, err.message));
                resolve(hash);
            })
        })
    }
    checkPassword(password, hash) {
        return new Promise((resolve, reject) => {
            bcrypt.compare(password, hash, (err, result) => {
                if(err || !result) reject(logger.logInvalid(403, 'incorrect password'));
                resolve(true);
            })
        })
    }
    validatePublicKey(key){
        return this.getPublicKeyPem().then(publicKey => {
            if(publicKey === key) return true;
            return Promise.reject(logger.logInvalid(403, 'Public key is not valid'));
        });
    }
    validateToken(token){
        try {
            return Promise.resolve(JWT.verify(token, this.publicKey));
        }
        catch(err){
            return Promise.reject(logger.logInvalid(403, err.message))
        }
    }
    getPublicKeyPem(){
        return this.loadDomainKeys()
            .then(async () => await jose.exportSPKI(this.publicKey))
            .catch(err => Promise.reject(logger.logInvalid(500, err.message)))
    }
    encryptString(string){
        if(!string) return Promise.reject(logger.logInvalid(500, 'No string found to encrypt'));
        try {
            const encrypted = this.RSAprivate.encryptPrivate(string, 'base64');
            return Promise.resolve(encrypted);
        }
        catch(err){
            return Promise.reject(logger.logInvalid(500, err.message));
        }
    }
}
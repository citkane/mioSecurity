if(!process.env.NODE_ENV) process.env.NODE_ENV = "development";
if(process.env.NODE_ENV !== 'development') {
    throw Error(`
POC extends to env "development" only.
    `)
}

const Keygen = require('./etc/Keygen');

let logger, api, adminRoles;
module.exports = class KeyManager extends Keygen {
    constructor(_logger, domain, config){
        super(_logger, domain, config);
        logger = _logger;
        adminRoles = config.get('adminRoles');
    }
    init(_api){
        api = _api;
        return this.initPersistance()
            .then(() => Promise.all([
                this.loadCache(),
                this.loadDomainKeys()
            ]))
            .then(() => {
                if(!this.cache.user[0]) return this.install().then(() => api.users.getUsers());
                return api.users.getUsers();                
            })

    }
    onConnect(){}
    install(){
        let details;
        return this.mio.prompt('createUser', `
This is the domain's installation.
Please create a super user.
        `)
        .then(d => details = d)
        .then(() => api.users.sanitizeUser(details))
        .then(d => details = d)
        .then(() => api.users.isValidPassword(details.password))
        .then(() => api.users.isValidEmail(details.email))
        .then(() => this.saveNewUser(0, details, 'super'))
        .then(() => this.saveUserPass(0, details.password))
        .catch(err => {
            if(err.message === 'canceled') throw 'canceled';
            logger.logError(err);
            return this.install();
        })
    }
    loginBroker(servicename, token){
        return this.validateToken(token).then(service => {
            if(service.credentials.username) return api.users.getUserById(service.credentials.uid).then(user => {
                if(user.credentials.username !== service.credentials.username) throw logger.logInvalid(403, 'Token mismatch');
                return true;
            })
            if(service.credentials.uid !== servicename) throw logger.logInvalid(403, 'Token mismatch');
            return true;
        })
    }
    loginUser(username, password){
        let user;
        return api.users.getUserByName(username)
            .then(_user => user = _user)
            .then(() => this.cache.userPass[user.credentials.uid])
            .then(hash => this.checkPassword(password, hash))
            .then(() => user)
    }
    getItem(type, uid){
        if(!this.cache[type] || !this.cache[type][uid]) return Promise.reject(logger.logInvalid(404, `${type} "${uid}" not found`));
        return Promise.resolve(this.cache[type][uid]);
    }
    getUsers(){
        return Promise.resolve(this.cache.user);
    }
    getServiceUser(serviceName){
        return this.getItem('service', serviceName).then(service => this.getItem('user', service.deployed.by))
    }
    validateServiceAdmin(user, serviceName, version, npm){
        const roles = user.roles;
        const grant = adminRoles.service.find(role => roles.indexOf(role) > -1);
        if(!grant) return Promise.reject(logger.logInvalid(403, 'User does not have admin permissions'));
        if(!this.cache.service[serviceName]) return this.saveNewService(serviceName, user.credentials.uid, version, npm);
        return Promise.resolve(true);
    }
    setServiceChallenge(servicename){
        return this.getChallenge('service', servicename).then(challenge => this.encryptString(challenge))
    }
    validateServiceChallenge(challengeResult){
        try {
            challengeResult = this.RSAprivate.decrypt(challengeResult, 'utf8');
            challengeResult = JSON.parse(challengeResult);
        }
        catch(err){
            throw logger.logInvalid(403, err.message);
        }
        return this.validateChallenge('service', challengeResult);
    }
}
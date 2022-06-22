const path = require('path');
const fs = require('fs-extra');
const { importPKCS8, importSPKI} = require('jose');
const NodeRSA = require('node-rsa');
const User = require('../lib/User');
const Service = require('../lib/Service');

const rootDir = '/mioScaffold/'
function findRootDir(dir){
    if(dir === '/') throw Error('Cannot save to root. Ensure the directory "mioScaffold" exists')
    return dir.endsWith(rootDir) ? dir : findRootDir(path.join(dir, '../'))
}

function makePaths(domain){
    const rootDir = findRootDir(__dirname);
    const store = path.join(rootDir, 'securityStore', domain, process.env.NODE_ENV);
    const userStore = path.join(rootDir, 'securityStore/user', process.env.NODE_ENV);

    const privateKeyPath = path.join(store, `${domain}_private.pem`);
    const publicKeyPath = path.join(store, `${domain}_public.pem`);

    const service = path.join(store, 'service');
    const servicePath = path.join(service, 'service.json');
    const serviceChecksumPath = path.join(service, 'serviceChecksum.json');

    const device = path.join(store, 'device');
    const devicePath = path.join(device, 'device.json');

    const userPath = path.join(userStore, 'users.json');
    const userPassPath = path.join(userStore, 'usersPass.json');

    [store, service, device, userStore].forEach(path => {
        if(!fs.existsSync(path)) fs.mkdirSync(path, { recursive: true });
    })

    const paths = {
        servicePath,
        serviceChecksumPath,
        devicePath,
        userPath,
        userPassPath
    }
    const keys = {
        privateKeyPath,
        publicKeyPath
    }
    return { paths, keys }
}

let logger, keys, paths;
module.exports = class Persistance {
    constructor(_logger, domain, config){
        logger = _logger;
        this.storage = config.get('authServer.storage');
        switch (this.storage) {
            case 'filesystem':
                ({keys, paths} = makePaths(domain))
                Object.keys(paths).forEach(key => {
                    const path = paths[key];
                    if(!fs.existsSync(path)) fs.writeJSONSync(path, {}, { spacing: 4 });
                })
                break;

            default:
                throw Error(`${this.storage}: Security store type not implemented.`)
        }

        this.cache = {};
    }
    initPersistance() {
        switch (this.storage) {
            case 'filesystem':
                if (
                    !fs.existsSync(keys.privateKeyPath) ||
                    !fs.existsSync(keys.publicKeyPath)
                ) return this.generateDomainKeys();
                return Promise.resolve()

            default:
                throw Error(`${this.storage}: Security store type not implemented.`)
        }        
    }
    noStore(){
        return Promise.reject(logger.logInvalid(500, `${this.storage}: Security store type not implemented.`));
    }
    loadCache(){
        const promises = [];
        switch (this.storage) {
            case 'filesystem':
                Object.keys(paths).forEach(key => {
                    const path = paths[key];
                    key = key.replace('Path', '');
                    promises.push(
                        fs.readJSON(path).then(data => this.cache[key] = data)
                    )
                })
                break;
            default:
                return this.noStore();
        }
        return Promise.all(promises);
    }
    saveCache(){
        const promises = [];
        switch (this.storage) {
            case 'filesystem':
                Object.keys(paths).forEach(key => {
                    const path = paths[key];
                    key = key.replace('Path', '');
                    promises.push(
                        fs.writeJSON(path, this.cache[key], { spaces: 4})
                    )
                })
                break;
            default:
                return this.noStore();
        }
        return Promise.all(promises);
    }

    loadDomainKeys(){
        switch (this.storage) {
            case 'filesystem':
                return Promise.all([
                    fs.readFile(keys.privateKeyPath),
                    fs.readFile(keys.publicKeyPath)
                ])
                .then(async (buffers) => {
                    this.privateKey = await importPKCS8(buffers[0].toString());
                    this.publicKey = await importSPKI(buffers[1].toString());
                    this.RSAprivate = new NodeRSA();
                    this.RSApublic = new NodeRSA();
                    this.RSAprivate.importKey(buffers[0]);
                    this.RSApublic.importKey(buffers[1]);
                })
                .catch(err => {
                    logger.logError(err);
                    return this.generateDomainKeys()
                })
            default:
                return this.noStore();
        }
    }
    savePrivateKey(key){
        switch (this.storage) {
            case 'filesystem':
                return fs.writeFile(keys.privateKeyPath, key).then(() => {
                    fs.chmodSync(keys.privateKeyPath, '00400');
                    return keys.privateKeyPath
                });
            default:
                return this.noStore();
        }
    }
    savePublicKey(key){
        switch (this.storage) {
            case 'filesystem':
                return fs.writeFile(keys.publicKeyPath, key).then(() => {
                    fs.chmodSync(keys.publicKeyPath, '00400');
                    return keys.publicKeyPath
                });
            default:
                return this.noStore();
        }
    }
    saveServiceChecksum(servicename, version, sum) {
        if(!this.cache.serviceChecksum[servicename]) this.cache.serviceChecksum[servicename] = {};
        if(!this.cache.serviceChecksum[servicename][version]) this.cache.serviceChecksum[servicename][version] = {};
        this.cache.serviceChecksum[servicename][version] = sum;
        switch (this.storage) {
            case 'filesystem':
                return fs.writeJSON(paths.serviceChecksumPath, this.cache.serviceChecksum, { spaces: 4});
            default:
                return this.noStore();
        }
    }
    saveNewService(servicename, adminUser, version, npm) {
        const service = {...new Service(servicename, adminUser, version, npm)}
        this.cache.service[servicename] = service;
        switch (this.storage) {
            case 'filesystem':
                return fs.writeJSON(paths.servicePath, this.cache.service, { spaces: 4});
            default:
                return this.noStore();
        }
    }
    saveNewUser(uid, newUser, role){
        const { username, firstname, lastname, email } = newUser;
        const user = {...new User(uid, username, email, role, firstname, lastname)}
        this.cache.user[uid] = user;
        switch (this.storage) {
            case 'filesystem':
                return fs.writeJSON(paths.userPath, this.cache.user, { spaces: 4}).then(() => user);
            default:
                return this.noStore();
        }
    }
    saveUserPass(uid, password){
        return this.hashPassword(password).then(hash => {
            this.cache.userPass[uid] = hash;
            switch (this.storage) {
                case 'filesystem':
                    return fs.writeJSON(paths.userPassPath, this.cache.userPass, { spaces: 4});
                default:
                    return this.noStore();
            }
        })
    }
}
const Persistance = require('./Persistance');
const uglify = require("uglify-es");
const checksum = require('checksum');
const crypto = require('crypto');

function cryptoRandomString(size=20){
    return crypto.randomBytes(size).toString('base64').slice(0, size);
}
function minify(string){
    const code = uglify.minify(string, {
        parse: {
            bare_returns: true
        },
        compress: false
    });
    if(code.error) throw code.error;
    return code.code;
}

let logger;
module.exports = class ChallengeDefs extends Persistance{
    constructor (_logger, domain, config){
        super(_logger, domain, config);
        logger = _logger;
        this.challengeCache = {
            service: {},
            device: {}
        };
        this.challenges = {
            service: {
                challenge: `
new Promise((resolve, reject) => {
    const salt = '${cryptoRandomString(20)}';
    const dir = path.join(require.main.filename, '../../');
    const version = fs.readJsonSync(path.join(dir, 'package.json')).version;
    const sums = {}
    Promise.all([
        hashElement(path.join(dir, 'package.json')).then(h => h.hash),
        hashElement(path.join(dir, 'src')).then(h => h.hash),
        hashElement(path.join(dir, 'node_modules/@mio-core/miosecurity/src')).then(h => h.hash),
        //hashElement(path.join(dir, 'node_modules/@mio-core/miosecurity/node_modules/mqtt/dist')).then(h => h.hash)
    ]).then(hashes => {
        sums.version = version;
        sums.src = checksum(hashes.join(''));
        sums.challenge = checksum(challenge);
        sums.serviceName = appDetails.uid;
        resolve(sums);
    })
});
                `,
                validate: (challengeResult) => {
                    const serviceName = challengeResult.serviceName;
                    const version = challengeResult.version;
                    let challengeSum = this.challengeCache.service[serviceName];
                    challengeSum = checksum(challengeSum);
                    if(challengeResult.challenge !== challengeSum) return Promise.reject(logger.logInvalid(403, 'challengeSum mismatch'));
                    /**
                     * TODO - tie this in with code repo checksums for production
                     */
                    if(
                        !this.cache.serviceChecksum[serviceName] ||
                        !this.cache.serviceChecksum[serviceName][version]
                    ) {
                        return this.saveServiceChecksum(serviceName, version, challengeResult.src)
                            .then(() => this.challenges.service.validate(challengeResult));
                    }
                    if(challengeResult.src !== this.cache.serviceChecksum[serviceName][version]) {
                        // return Promise.reject(logger.logInvalid(403, 'source code mismatch'));
                    }
                    return Promise.resolve(true);
                }
            }
        /**
         * TODO - further logic for field devices / variants goes here.
         */
        }
    }
    getChallenge(def, servicename) {
        if(!this.challenges[def]) return Promise.reject(404, `Command def "${def}" not found`);
        try{
            const challenge = minify(this.challenges[def].challenge);
            this.challengeCache.service[servicename] = challenge;
            return Promise.resolve(challenge);
        }
        catch(err){
            return Promise.reject(logger.logInvalid(500, err.message))
        }

    }
    validateChallenge(def, challengeResult){
        return this.challenges[def].validate(challengeResult);
    }
}
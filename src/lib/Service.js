module.exports = class Service {
    constructor(uid, owner, version, npm){
        this.credentials = {
            uid
        };
        this.deployed = {
            time: Date.now(),
            by: owner,
            version,
            npm
        }
        this.upgraded = {}
        this.roles = [];
        this.groups = [];
        this.admins = [owner];
        this.meta = {};
    }
}
module.exports = class User {
    constructor(uid, username, email, role, firstname, lastname){
        this.credentials = {
            uid,
            username,
            email,
            firstname,
            lastname
        };
        this.roles = [role];
        this.groups = [];
        this.preferences = {};
        this.meta = {};
    }
}
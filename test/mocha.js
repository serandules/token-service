var nconf = require('nconf');

nconf.overrides({
    'services': [
        {"name": "service-configs", "version": "master", "domain": "accounts", "prefix": "/apis/v/configs"},
        {"name": "service-users", "version": "master", "domain": "accounts", "prefix": "/apis/v/users"},
        {"name": "service-clients", "version": "master", "domain": "accounts", "prefix": "/apis/v/clients"},
        {"path": __dirname + '/..', "domain": "accounts", "prefix": "/apis/v/tokens"}
    ]
});
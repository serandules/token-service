var nconf = require('nconf');

nconf.overrides({
    "SERVICE_CONFIGS": "master:www:/apis/v/configs",
    "SERVICE_USERS": "master:accounts:/apis/v/users",
    "SERVICE_CLIENTS": "master:accounts:/apis/v/clients",
    "LOCAL_TOKENS": __dirname + "/..:accounts:/apis/v/tokens"
});

require('pot');

var nconf = require('nconf');

nconf.overrides({
    "SERVICE_CONFIGS": "master:apis:/v/configs",
    "SERVICE_USERS": "master:apis:/v/users",
    "SERVICE_CLIENTS": "master:apis:/v/clients",
    "LOCAL_TOKENS": __dirname + "/..:apis:/v/tokens"
});

require('pot');

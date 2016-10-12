var log = require('logger')('token-service');
var request = require('request');
var async = require('async');
var url = require('url');
var utils = require('utils');
var permission = require('permission');
var User = require('user');
var Client = require('client');
var Token = require('token');
var Config = require('config');

var express = require('express');
var router = express.Router();

module.exports = router;

var MIN_ACCESSIBILITY = 20 * 1000;

var REDIRECT_URI = utils.resolve('accounts://auth/oauth');

var context = {
    serandives: {},
    facebook: {
        token: 'https://graph.facebook.com/v2.3/oauth/access_token',
        profile: 'https://graph.facebook.com/me'
    }
};

Client.findOne({
    name: 'serandives'
}, function (err, client) {
    if (err) {
        throw err;
    }
    if (!client) {
        throw new Error('no serandives client found in the database');
    }
    var serandives = context.serandives;
    serandives.id = client.id;
    serandives.secret = client.secret;
});

Config.findOne({
    name: 'facebook'
}, function (err, config) {
    if (err) {
        throw err;
    }
    if (!config) {
        throw new Error('no facebook config found in the database');
    }
    config = JSON.parse(config.value);
    var app = config.app;
    var facebook = context.facebook;
    facebook.id = app.id;
    facebook.secret = app.secret;
});

var refreshError = function (err, req, res) {
    var serand = req.serand;
    var code = err.code;
    if (code === 11000) {
        // cannot acquire lock
        serand.refreshed = serand.refreshed || 0;
        if (serand.refreshed < 4) {
            serand.refreshed++
            return setTimeout(refreshGrant, 500, req, res);
        }
        res.status(409).send([{
            code: 409,
            message: 'Conflict'
        }]);
        return;
    }
    log.error(err);
    res.status(500).send([{
        code: 500,
        message: 'Internal Server Error'
    }]);
}

var sendToken = function (clientId, res, user) {
    Client.findOne({
        _id: clientId
    }, function (err, client) {
        if (err) {
            log.error(err);
            res.status(500).send([{
                code: 500,
                message: 'Internal Server Error'
            }]);
            return;
        }
        if (!client) {
            res.status(401).send([{
                code: 401,
                message: 'Unauthorized'
            }]);
            return;
        }
        Token.findOne({
            user: user.id,
            client: client.id
        }, function (err, token) {
            if (err) {
                log.error(err);
                res.status(500).send([{
                    code: 500,
                    message: 'Internal Server Error'
                }]);
                return;
            }
            var expires;
            if (token) {
                expires = token.accessibility();
                if (expires > MIN_ACCESSIBILITY) {
                    res.send({
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: expires
                    });
                    return;
                }
            }
            Token.create({
                user: user.id,
                client: client.id
            }, function (err, token) {
                if (err) {
                    log.error(err);
                    res.status(500).send([{
                        code: 500,
                        message: 'Internal Server Error'
                    }]);
                    return;
                }
                res.send({
                    id: token.id,
                    access_token: token.access,
                    refresh_token: token.refresh,
                    expires_in: token.accessible
                });
            });
        });
    });
};

var passwordGrant = function (req, res) {
    User.findOne({
        email: req.body.username
    }).populate('tokens').exec(function (err, user) {
        if (err) {
            log.error(err);
            res.status(500).send([{
                code: 500,
                message: 'Internal Server Error'
            }]);
            return;
        }
        if (!user) {
            res.status(401).send([{
                code: 401,
                message: 'Unauthorized'
            }]);
            return;
        }
        user.auth(req.body.password, function (err, auth) {
            if (err) {
                log.error(err);
                res.status(500).send([{
                    code: 500,
                    message: 'Internal Server Error'
                }]);
                return;
            }
            if (!auth) {
                res.status(401).send([{
                    code: 401,
                    message: 'Unauthorized'
                }]);
                return;
            }
            sendToken(req.body.client_id, res, user);
        });
    });
};

var sendRefreshToken = function (req, res, done) {
    Token.findOne({
        refresh: req.body.refresh_token
    }).populate('client')
        .exec(function (err, token) {
            if (err) {
                log.error(err);
                res.status(500).send([{
                    code: 500,
                    message: 'Internal Server Error'
                }]);
                return done();
            }
            if (!token) {
                res.status(401).send([{
                    code: 401,
                    message: 'Unauthorized'
                }]);
                return done();
            }
            var expin = token.refreshability();
            if (expin === 0) {
                res.status(401).send([{
                    code: 401,
                    message: 'Unauthorized'
                }]);
                return done();
            }
            expin = token.accessibility();
            if (expin > MIN_ACCESSIBILITY) {
                res.send({
                    access_token: token.access,
                    refresh_token: token.refresh,
                    expires_in: expin
                });
                return done();
            }
            Token.refresh(token.id, function (err) {
                var code
                if (err) {
                    code = err.code;
                    if (code === 11000) {
                        // since a pending retry exists, it will be retried
                        return done(err);
                    }
                    log.error(err);
                    res.status(500).send([{
                        code: 500,
                        message: 'Internal Server Error'
                    }]);
                    return done()
                }
                Token.findOne({
                    _id: token.id
                }, function (err, token) {
                    if (err) {
                        log.error(err);
                        res.status(500).send([{
                            code: 500,
                            message: 'Internal Server Error'
                        }]);
                        return done();
                    }
                    res.send({
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: token.accessible
                    });
                    done()
                });
            });
        });
};

var refreshGrant = function (req, res) {
    async.retry({times: 4, interval: 500}, function (tried) {
        sendRefreshToken(req, res, tried)
    }, function (err) {
        if (err) {
            res.status(409).send([{
                code: 409,
                message: 'Conflict'
            }]);
        }
    })
};

var facebookGrant = function (req, res) {
    var serandives = context.serandives;
    var facebook = context.facebook;
    request({
        method: 'GET',
        uri: facebook.token,
        qs: {
            code: req.body.code,
            client_id: facebook.id,
            client_secret: facebook.secret,
            redirect_uri: REDIRECT_URI
        },
        json: true
    }, function (err, response, body) {
        if (err) {
            log.error(err);
            res.status(500).send([{
                code: 500,
                message: 'Internal Server Error'
            }]);
            return;
        }
        if (response.statusCode !== 200) {
            res.status(401).send([{
                code: 401,
                message: 'Unauthorized'
            }]);
            return;
        }
        var access = body.access_token;
        request({
            method: 'GET',
            uri: facebook.profile,
            qs: {
                access_token: access,
                fields: 'email,first_name,last_name'
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                log.error(err);
                res.status(500).send([{
                    code: 500,
                    message: 'Internal Server Error'
                }]);
                return;
            }
            if (response.statusCode !== 200) {
                res.status(401).send([{
                    code: 401,
                    message: 'Unauthorized'
                }]);
                return;
            }
            var email = body.email;
            if (!email) {
                log.error(err);
                res.status(500).send([{
                    code: 500,
                    message: 'Internal Server Error'
                }]);
                return;
            }
            User.findOne({
                email: email
            }).populate('tokens').exec(function (err, user) {
                if (err) {
                    log.error(err);
                    res.status(500).send([{
                        code: 500,
                        message: 'Internal Server Error'
                    }]);
                    return;
                }
                if (user) {
                    return sendToken(serandives.id, res, user);
                }
                User.create({
                    email: email,
                    firstname: body.first_name || '',
                    lastname: body.last_name || ''
                }, function (err, user) {
                    if (err) {
                        log.error(err);
                        res.status(500).send([{
                            code: 500,
                            message: 'Internal Server Error'
                        }]);
                        return;
                    }
                    sendToken(serandives.id, res, user);
                });
            });
        })
    });
};

router.get('/tokens/:id', function (req, res) {
    var token = req.token;
    if (!token) {
        res.status(401).send([{
            code: 401,
            message: 'Unauthorized'
        }]);
        return;
    }
    if (!token.can('tokens:' + req.params.id, 'read', token)) {
        res.status(401).send([{
            code: 401,
            message: 'Unauthorized'
        }]);
        return;
    }
    token.has = permission.merge(token.has, token.client.has, token.user.has);
    res.send({
        id: token.id,
        user: token.user.id,
        client: token.client.id,
        access: token.access,
        refresh: token.refresh,
        created: token.created,
        accessible: token.accessible,
        refreshable: token.refreshable,
        has: token.has
    });
});

/**
 * grant_type=password&username=ruchira&password=ruchira
 * grant_type=refresh_token&refresh_token=123456
 */
router.post('/tokens', function (req, res) {
    switch (req.body.grant_type) {
        case 'password':
            passwordGrant(req, res);
            break;
        case 'refresh_token':
            refreshGrant(req, res);
            break;
        case 'facebook':
            facebookGrant(req, res);
            break;
        default :
            res.status(400).send([{
                code: 400,
                message: 'Bad Grant Type Request'
            }]);
    }
});

router.delete('/tokens/:id', function (req, res) {
    var token = req.params.id;
    Token.findOne({
            access: token
        })
        .exec(function (err, token) {
            if (err) {
                log.error(err);
                res.status(500).send([{
                    code: 500,
                    message: 'Internal Server Error'
                }]);
                return;
            }
            if (!token) {
                res.status(401).send([{
                    code: 401,
                    message: 'Unauthorized'
                }]);
                return;
            }
            token.remove();
            res.status(204).end();
        });
});

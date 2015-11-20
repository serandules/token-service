var log = require('logger')('token-service');
var permission = require('permission');
var User = require('user');
var Client = require('client');
var Token = require('token');

var express = require('express');
var router = express.Router();

module.exports = router;

var MIN_ACCESSIBILITY = 20 * 1000;

var sendToken = function (req, res, client, user) {
    Token.findOne({
        user: user.id,
        client: client.id
    }, function (err, token) {
        if (err) {
            log.error(err);
            res.status(500).send({
                error: 'internal server error'
            });
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
                res.status(500).send({
                    error: 'internal server error'
                });
                return;
            }
            User.update({
                _id: user.id
            }, {
                token: token
            }, function (err, user) {
                if (err) {
                    log.error(err);
                    res.status(500).send({
                        error: 'internal server error'
                    });
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
            res.status(500).send({
                error: 'internal server error'
            });
            return;
        }
        if (!user) {
            res.status(401).send({
                error: 'user not authorized'
            });
            return;
        }
        user.auth(req.body.password, function (err, auth) {
            if (err) {
                log.error(err);
                res.status(500).send({
                    error: 'internal server error'
                });
                return;
            }
            if (!auth) {
                res.status(401).send({
                    error: 'user not authorized'
                });
                return;
            }
            Client.findOne({
                _id: req.body.client_id
            }, function (err, client) {
                if (err) {
                    log.error(err);
                    res.status(500).send({
                        error: 'internal server error'
                    });
                    return;
                }
                if (!client) {
                    res.status(404).send({
                        error: 'client id not found'
                    });
                    return;
                }
                sendToken(req, res, client, user);
            });
        });
    });
};

var refreshGrant = function (req, res) {
    Token.findOne({
        refresh: req.body.refresh_token
    }).populate('client')
        .exec(function (err, token) {
            if (err) {
                log.error(err);
                res.status(500).send({
                    error: 'internal server error'
                });
                return;
            }
            if (!token) {
                res.status(401).send({
                    error: 'token not authorized'
                });
                return;
            }
            var expin = token.refreshability();
            if (expin === 0) {
                res.status(401).send({
                    error: 'refresh token expired'
                });
                return;
            }
            expin = token.accessibility();
            if (expin > MIN_ACCESSIBILITY) {
                res.send({
                    access_token: token.access,
                    refresh_token: token.refresh,
                    expires_in: expin
                });
                return;
            }
            var user = token.user;
            var client = token.client;
            Token.create({
                user: user.id,
                client: client.id
            }, function (err, token) {
                if (err) {
                    log.error(err);
                    res.status(500).send({
                        error: 'internal server error'
                    });
                    return;
                }
                User.update({
                    _id: user.id
                }, {
                    token: token
                }, function (err, user) {
                    if (err) {
                        log.error(err);
                        res.status(500).send({
                            error: 'internal server error'
                        });
                        return;
                    }
                    res.send({
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: token.accessible
                    });
                });
            });
        });
};

router.get('/tokens/:id', function (req, res) {
    var token = req.token;
    if (!token) {
        res.status(404).send({
            error: 'specified token cannot be found'
        });
        return;
    }
    if (!token.can('tokens:' + req.params.id, 'read', token)) {
        res.status(401).send({
            error: 'unauthorized access for token'
        });
        return;
    }
    res.send(permission.merge(token.has, token.client.has, token.user.has));
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
        default :
            res.status(400).send({
                error: 'unsupported grant type'
            });
    }
});

router.delete('/tokens/:id', function (req, res) {
    var token = req.params.id;
    Token.findOne({
        access: token
    })
        .exec(function (err, token) {
            if (err) {
                res.status(500).send({
                    error: 'error while retrieving the token'
                });
                return;
            }
            if (!token) {
                res.status(404).send({
                    error: 'specified token cannot be found'
                });
                return;
            }
            token.remove();
            res.status(200).send({
                error: false
            });
        });
});

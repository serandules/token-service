var log = require('logger')('token-service:index');
var User = require('user');
var Client = require('client');
var mongoose = require('mongoose');
var Token = require('token');

var express = require('express');
var router = express.Router();

module.exports = router;

var MIN_ACCESSIBILITY = 20 * 1000;

var su = {
    email: 'admin@serandives.com'
};

var sc = 'serandives.com';

var ssc = function (user) {
    Client.create({
        name: sc,
        user: user
    }, function (err, client) {
        if (err) {
            throw err;
        }
        sc = client;
    });
};

User.findOne({
    email: su.email
}).exec(function (err, user) {
    if (err) {
        throw err;
    }
    if (user) {
        su = user;
        ssc(user);
        return;
    }

    var suPass = process.env.SU_PASS;
    if (!suPass) {
        throw 'su password cannot be found. Please specify it using SU_PASS';
    }

    su.password = suPass;
    User.create(su, function (err, user) {
        if (err) {
            throw err;
        }
        su = user;
        ssc(user);
    });
});

var passwordGrant = function (req, res) {
    User.findOne({
        email: req.body.username
    }).populate('token').exec(function (err, user) {
        if (err) {
            console.error(err);
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
                res.status(500).send({
                    error: err
                });
                return;
            }
            if (!auth) {
                res.status(401).send({
                    error: 'user not authorized'
                });
                return;
            }
            var expin;
            var token = user.token;
            if (token) {
                expin = token.accessibility();
                if (expin > MIN_ACCESSIBILITY) {
                    res.send({
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: expin
                    });
                    return;
                }
            }
            Token.create({
                user: user.id,
                client: sc
            }, function (err, token) {
                if (err) {
                    res.status(500).send({
                        error: err
                    });
                    return;
                }
                User.update({
                    _id: user.id
                }, {
                    token: token
                }, function (err, user) {
                    if (err) {
                        res.status(500).send({
                            error: err
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
    });
};


var refreshGrant = function (req, res) {
    Token.findOne({
        refresh: req.body.refresh_token
    }).exec(function (err, token) {
        if (err) {
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
        Token.create({
            user: user,
            client: sc
        }, function (err, token) {
            if (err) {
                res.status(500).send({
                    error: err
                });
                return;
            }
            User.update({
                _id: user
            }, {
                token: token
            }, function (err, user) {
                if (err) {
                    res.status(500).send({
                        error: err
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

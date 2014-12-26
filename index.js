var User = require('user');
var Client = require('client');
var mongoose = require('mongoose');
var Token = require('token');

var express = require('express');
var app = module.exports = express();

app.use(express.json());
app.use(express.urlencoded());

var MIN_TOKEN_VALIDITY = 40 * 1000;

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

var expires = function (token) {
    var exin = token.created.getTime() + token.validity - new Date().getTime();
    return exin > 0 ? exin : 0;
};

var passwordGrant = function (req, res) {
    User.findOne({
        email: req.body.username
    }).populate('token').exec(function (err, user) {
        if (err) {
            console.error(err);
            res.send(500, {
                error: 'internal server error'
            });
            return;
        }
        if (!user) {
            res.send(401, {
                error: 'user not authorized'
            });
            return;
        }
        user.auth(req.body.password, function (err, auth) {
            if (err) {
                res.send(500, {
                    error: err
                });
                return;
            }
            if (!auth) {
                res.send(401, {
                    error: 'user not authorized'
                });
                return;
            }
            var token = user.token;
            if (token) {
                if (expires(token) > MIN_TOKEN_VALIDITY) {
                    res.send({
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: token.validity
                    });
                    return;
                }
            }
            Token.create({
                user: user.id,
                client: sc
            }, function (err, token) {
                if (err) {
                    res.send(500, {
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
                        res.send(500, {
                            error: err
                        });
                        return;
                    }
                    res.send({
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: token.validity
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
            console.error(err);
            res.send(500, {
                error: 'internal server error'
            });
            return;
        }
        if (!token) {
            res.send(401, {
                error: 'token not authorized'
            });
            return;
        }
        var expin = expires(token);
        if (expin === 0) {
            res.send(401, {
                error: 'token expired'
            });
            return;
        }
        if (expin > MIN_TOKEN_VALIDITY) {
            res.send({
                access_token: token.access,
                refresh_token: token.refresh,
                expires_in: token.validity
            });
            return;
        }
        var user = token.user.id;
        Token.create({
            user: user,
            client: sc
        }, function (err, token) {
            if (err) {
                res.send(500, {
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
                    res.send(500, {
                        error: err
                    });
                    return;
                }
                res.send({
                    access_token: token.access,
                    refresh_token: token.refresh,
                    expires_in: token.validity
                });
            });
        });
    });
};

/**
 * grant_type=password&username=ruchira&password=ruchira
 * grant_type=refresh_token&refresh_token=123456
 */
app.post('/tokens', function (req, res) {
    switch (req.body.grant_type) {
        case 'password':
            passwordGrant(req, res);
            break;
        case 'refresh_token':
            refreshGrant(req, res);
            break;
        default :
            res.send(400, {
                error: 'unsupported grant type'
            });
    }
});

app.delete('/tokens/:id', function (req, res) {
    var token = req.params.id;
    Token.findOne({
        access: token
    })
        .exec(function (err, token) {
            if (err) {
                res.send(500, {
                    error: 'error while retrieving the token'
                });
                return;
            }
            if (!token) {
                res.send(404, {
                    error: 'specified token cannot be found'
                });
                return;
            }
            token.remove();
            res.send(200, {
                error: false
            });
        });
});

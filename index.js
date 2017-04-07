var log = require('logger')('token-service');
var nconf = require('nconf');
var request = require('request');
var async = require('async');
var url = require('url');
var express = require('express');
var bodyParser = require('body-parser');

var errors = require('errors');
var utils = require('utils');
var permission = require('permission');
var User = require('user');
var Client = require('client');
var Token = require('token');
var auth = require('auth');
var serandi = require('serandi');
var locate = require('locate');

module.exports = function (router) {
    router.use(serandi.pond);
    router.use(serandi.ctx);
    router.use(auth({
        open: [
            '^\/$'
        ],
        hybrid: [
            '^\/.*'
        ]
    }));
    router.use(bodyParser.json());
    router.use(serandi.locate('/apis/v'));

    var MIN_ACCESSIBILITY = 20 * 1000;

    var REDIRECT_URI = utils.resolve('accounts://auth/oauth');

    var context = {
        serandives: {},
        facebook: {
            id: nconf.get('facebookId'),
            secret: nconf.get('facebookSecret'),
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

    var sendToken = function (clientId, res, user) {
        Client.findOne({
            _id: clientId
        }, function (err, client) {
            if (err) {
                log.error(err);
                return res.pond(errors.serverError());
            }
            if (!client) {
                return res.pond(errors.unauthorized());
            }
            Token.findOne({
                user: user.id,
                client: client.id
            }, function (err, token) {
                if (err) {
                    log.error(err);
                    return res.pond(errors.serverError());
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
                        return res.pond(errors.serverError());
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
                return res.pond(errors.serverError());
            }
            if (!user) {
                return res.pond(res.unauthorized());
            }
            user.auth(req.body.password, function (err, auth) {
                if (err) {
                    log.error(err);
                    return res.pond(errors.serverError());
                }
                if (!auth) {
                    return res.pond(res.unauthorized());
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
                    res.pond(errors.serverError());
                    return done();
                }
                if (!token) {
                    res.unauthorized();
                    return done();
                }
                var expin = token.refreshability();
                if (expin === 0) {
                    res.unauthorized();
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
                        res.pond(errors.serverError());
                        return done()
                    }
                    Token.findOne({
                        _id: token.id
                    }, function (err, token) {
                        if (err) {
                            log.error(err);
                            res.pond(errors.serverError());
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
                res.pond(errors.conflict('Token Conflict'));
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
                return res.pond(errors.serverError());
            }
            if (response.statusCode !== 200) {
                return res.pond(errors.unauthorized());
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
                    return res.pond(errors.serverError());
                }
                if (response.statusCode !== 200) {
                    return res.pond(errors.unauthorized());
                }
                var email = body.email;
                if (!email) {
                    log.error(err);
                    return res.pond(errors.serverError());
                }
                User.findOne({
                    email: email
                }).populate('tokens').exec(function (err, user) {
                    if (err) {
                        log.error(err);
                        return res.pond(errors.serverError());
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
                            return res.pond(errors.serverError());
                        }
                        sendToken(serandives.id, res, user);
                    });
                });
            })
        });
    };

    router.get('/:id', function (req, res) {
        var token = req.token;
        if (!token) {
            return res.pond(errors.unauthorized());
        }
        if (!token.can('tokens:' + req.params.id, 'read', token)) {
            return res.pond(errors.unauthorized());
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
    router.post('/', function (req, res) {
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
                res.pond(errors.badRequest('Bad Grand Type Request'));
        }
    });

    router.delete('/:id', function (req, res) {
        var token = req.params.id;
        Token.findOne({
            access: token
        })
            .exec(function (err, token) {
                if (err) {
                    log.error(err);
                    return res.pond(errors.serverError());
                }
                if (!token) {
                    return res.pond(errors.unauthorized());
                }
                token.remove();
                res.status(204).end();
            });
    });
};
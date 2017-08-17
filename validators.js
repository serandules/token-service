var log = require('logger')('token-service:validators');
var async = require('async');

var errors = require('errors');
var validators = require('validators');
var utils = require('utils');
var Tokens = require('model-tokens');
var Users = require('model-users');

var REDIRECT_URI = utils.resolve('accounts://auth/oauth');

var MIN_ACCESSIBILITY = 20 * 1000;

exports.MIN_ACCESSIBILITY = MIN_ACCESSIBILITY;

var passwordGrant = function (req, res, next) {
    var data = req.body;
    var username = data.username;
    if (!username) {
        return res.pond(errors.unprocessableEntity('\'username\' needs to be specified'));
    }
    var password = data.password;
    if (!password) {
        return res.pond(errors.unprocessableEntity('\'password\' needs to be specified'));
    }
    var client_id = data.client_id;
    if (!client_id) {
        return res.pond(errors.unprocessableEntity('\'client_id\' needs to be specified'));
    }
    Users.findOne({
        email: req.body.username
    }).populate('tokens').exec(function (err, user) {
        if (err) {
            log.error(err);
            return res.pond(errors.serverError());
        }
        if (!user) {
            return res.pond(errors.unauthorized());
        }
        user.auth(req.body.password, function (err, auth) {
            if (err) {
                log.error(err);
                return res.pond(errors.serverError());
            }
            if (!auth) {
                return res.pond(errors.unauthorized());
            }
            req.user = user;
            req.body = {client: req.body.client_id};
            next();
        });
    });
};

var sendRefreshToken = function (req, res, done) {
    Tokens.findOne({
        refresh: req.body.refresh_token
    }).populate('client')
        .exec(function (err, token) {
            if (err) {
                log.error(err);
                res.pond(errors.serverError());
                return done();
            }
            if (!token) {
                res.pond(errors.unauthorized());
                return done();
            }
            var expin = token.refreshability();
            if (expin === 0) {
                res.pond(errors.unauthorized());
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
            Tokens.refresh(token.id, function (err) {
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
                Tokens.findOne({
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
                    done();
                });
            });
        });
};

var refreshGrant = function (req, res) {
    var data = req.body;
    var refreshToken = data.refresh_token;
    if (!refreshToken) {
        return res.pond(errors.unprocessableEntity('\'refresh_token\' needs to be specified'));
    }
    async.retry({times: 4, interval: 500}, function (tried) {
        sendRefreshToken(req, res, tried)
    }, function (err) {
        if (err) {
            res.pond(errors.conflict());
        }
    });
};

var facebookGrant = function (req, res, next) {
    var code = data.code;
    if (!code) {
        return res.pond(errors.unprocessableEntity('\'code\' needs to be specified'));
    }
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
            Users.findOne({
                email: email
            }).populate('tokens').exec(function (err, user) {
                if (err) {
                    log.error(err);
                    return res.pond(errors.serverError());
                }
                if (user) {
                    req.user = user;
                    req.body = {client: serandives.id};
                    return next();
                }
                Users.create({
                    email: email,
                    firstname: body.first_name || '',
                    lastname: body.last_name || ''
                }, function (err, user) {
                    if (err) {
                        log.error(err);
                        return res.pond(errors.serverError());
                    }
                    req.user = user;
                    req.body = {client: serandives.id};
                    next();
                });
            });
        })
    });
};

exports.create = function (req, res, next) {
    validators.create({
        model: Tokens
    }, req, res, next);
};

exports.grant = function (req, res, next) {
    var type = req.body.grant_type;
    if (type === 'password') {
        return passwordGrant(req, res, next);
    }
    if (type === 'refresh_token') {
        return refreshGrant(req, res, next);
    }
    if (type === 'facebook') {
        return facebookGrant(req, res, next);
    }
    res.pond(errors.unprocessableEntity('Invalid grand type request'));
};
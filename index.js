var log = require('logger')('token-service');
var express = require('express');
var bodyParser = require('body-parser');
var nconf = require('nconf');
var request = require('request');
var async = require('async');
var url = require('url');

var errors = require('errors');
var utils = require('utils');
var permission = require('permission');
var auth = require('auth');
var serandi = require('serandi');
var Clients = require('model-clients');
var Tokens = require('model-tokens');

var validators = require('./validators');
var sanitizers = require('./sanitizers');

var MIN_ACCESSIBILITY = validators.MIN_ACCESSIBILITY;

var context = {
    serandives: {},
    facebook: {
        id: nconf.get('facebookId'),
        secret: nconf.get('facebookSecret'),
        token: 'https://graph.facebook.com/v2.3/oauth/access_token',
        profile: 'https://graph.facebook.com/me'
    }
};

Clients.findOne({
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

var sendToken = function (req, res) {
    var clientId = req.body.client;
    Clients.findOne({
        _id: clientId
    }, function (err, client) {
        if (err) {
            log.error(err);
            return res.pond(errors.serverError());
        }
        if (!client) {
            return res.pond(errors.unauthorized());
        }
        Tokens.findOne({
            user: req.user.id,
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
                        id: token.id,
                        access_token: token.access,
                        refresh_token: token.refresh,
                        expires_in: expires
                    });
                    return;
                }
            }
            Tokens.createIt(req, res, req.body, function (err, token) {
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

module.exports = function (router) {
    router.use(serandi.pond);
    router.use(serandi.ctx);
    router.use(auth({
        GET: {
            open: [
                '^\/$'
            ],
            hybrid: [
                '^\/.*'
            ]
        },
        POST: {
            open: [
                '^\/$'
            ],
            hybrid: [
                '^\/.*'
            ]
        }
    }));
    router.use(bodyParser.json());

    router.get('/:id', function (req, res) {
        var token = req.token;
        if (!token) {
            return res.pond(errors.unauthorized());
        }
        if (!token.can('tokens:' + req.params.id, 'read', token)) {
            return res.pond(errors.unauthorized());
        }
        token.has = permission.merge(token.has, token.client.has, req.user.has);
        res.send({
            id: token.id,
            user: req.user.id,
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
    router.post('/', validators.grant, validators.create, sanitizers.create, function (req, res) {
        sendToken(req, res);
    });

    router.delete('/:id', function (req, res) {
        var token = req.params.id;
        Tokens.remove({
            access: token
        }, function (err) {
            if (err) {
                log.error(err);
                return res.pond(errors.serverError());
            }
            res.status(204).end();
        });
    });
};
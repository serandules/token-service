var log = require('logger')('service-token:test:find');
var should = require('should');
var request = require('request');
var pot = require('pot');
var mongoose = require('mongoose');
var errors = require('errors');

describe('GET /clients', function () {
    var serandivesId;
    var user;
    var accessToken;
    var clientId;
    before(function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/configs/boot'),
            method: 'GET',
            json: true
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(200);
            should.exist(b);
            should.exist(b.name);
            b.name.should.equal('boot');
            should.exist(b.value);
            should.exist(b.value.clients);
            should.exist(b.value.clients.serandives);
            serandivesId = b.value.clients.serandives;
            request({
                uri: pot.resolve('accounts', '/apis/v/users'),
                method: 'POST',
                json: {
                    email: 'user@serandives.com',
                    password: '1@2.Com'
                }
            }, function (e, r, b) {
                if (e) {
                    return done(e);
                }
                r.statusCode.should.equal(201);
                should.exist(b);
                should.exist(b.id);
                should.exist(b.email);
                b.email.should.equal('user@serandives.com');
                user = b;
                request({
                    uri: pot.resolve('accounts', '/apis/v/tokens'),
                    method: 'POST',
                    form: {
                        client_id: serandivesId,
                        grant_type: 'password',
                        username: 'user@serandives.com',
                        password: '1@2.Com'
                    },
                    json: true
                }, function (e, r, b) {
                    if (e) {
                        return done(e);
                    }
                    r.statusCode.should.equal(200);
                    should.exist(b.access_token);
                    should.exist(b.refresh_token);
                    accessToken = b.access_token;
                    request({
                        uri: pot.resolve('accounts', '/apis/v/clients'),
                        method: 'POST',
                        json: {
                            name: 'serandives',
                            to: ['http://test.serandives.com/dummy']
                        },
                        auth: {
                            bearer: accessToken
                        }
                    }, function (e, r, b) {
                        if (e) {
                            return done(e);
                        }
                        r.statusCode.should.equal(201);
                        should.exist(b);
                        should.exist(b.id);
                        should.exist(b.name);
                        should.exist(b.to);
                        b.name.should.equal('serandives');
                        b.to.length.should.equal(1);
                        b.to[0].should.equal('http://test.serandives.com/dummy');
                        clientId = b.id;
                        done();
                    });
                });
            });
        });
    });

    it('GET /clients/:id unauthorized', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/clients/' + clientId),
            method: 'GET',
            json: true
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unauthorized().status);
            should.exist(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unauthorized().data.code);
            done();
        });
    });

    it('GET /users/:id', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/clients/' + clientId),
            method: 'GET',
            auth: {
                bearer: accessToken
            },
            json: true
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(200);
            should.exist(b);
            should.exist(b.id);
            should.exist(b.name);
            b.id.should.equal(clientId);
            b.name.should.equal('serandives');
            done();
        });
    });
});
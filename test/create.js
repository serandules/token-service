var log = require('logger')('service-token:test:create');
var errors = require('errors');
var should = require('should');
var request = require('request');
var pot = require('pot');

describe('POST /tokens', function () {
    var client;
    before(function (done) {
        pot.start(function (err) {
            if (err) return done(err);
            pot.client(function (err, c) {
                if (err) return done(err);
                client = c;
                done();
            });
        });
    });

    after(function (done) {
        pot.stop(done);
    });

    it('with no media type', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            auth: {
                bearer: client.users[0].token
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unsupportedMedia().status);
            should.exist(b);
            b = JSON.parse(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unsupportedMedia().data.code);
            done();
        });
    });

    it('with unsupported media type', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            headers: {
                'Content-Type': 'application/xml'
            },
            auth: {
                bearer: client.users[0].token
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unsupportedMedia().status);
            should.exist(b);
            b = JSON.parse(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unsupportedMedia().data.code);
            done();
        });
    });

    it('with unsupported grant type', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            json: {
                grant_type: 'custom'
            },
            auth: {
                bearer: client.users[0].token
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unprocessableEntity().status);
            should.exist(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unprocessableEntity().data.code);
            done();
        });
    });

    it('password grand type without username', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            json: {
                grant_type: 'password'
            },
            auth: {
                bearer: client.users[0].token
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unprocessableEntity().status);
            should.exist(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unprocessableEntity().data.code);
            done();
        });
    });

    it('password grand type without password', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            json: {
                grant_type: 'password',
                username: 'user@serandives.com'
            },
            auth: {
                bearer: client.users[0].token
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unprocessableEntity().status);
            should.exist(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unprocessableEntity().data.code);
            done();
        });
    });

    it('password grand type without client_id', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            json: {
                grant_type: 'password',
                username: 'user@serandives.com',
                password: '123456'
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(errors.unprocessableEntity().status);
            should.exist(b);
            should.exist(b.code);
            should.exist(b.message);
            b.code.should.equal(errors.unprocessableEntity().data.code);
            done();
        });
    });

    it('password grand type with unauthorized password', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            json: {
                client_id: client.serandivesId,
                grant_type: 'password',
                username: 'user@serandives.com',
                password: '123456'
            }
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

    it('password grant type with valid password', function (done) {
        request({
            uri: pot.resolve('accounts', '/apis/v/tokens'),
            method: 'POST',
            json: {
                client_id: client.serandivesId,
                grant_type: 'password',
                username: 'user@serandives.com',
                password: '1@2.Com'
            }
        }, function (e, r, b) {
            if (e) {
                return done(e);
            }
            r.statusCode.should.equal(200);
            should.exist(b);
            should.exist(b.id);
            should.exist(b.access_token);
            should.exist(b.refresh_token);
            should.exist(b.expires_in);
            b.expires_in.should.be.above(0)
            request({
                uri: pot.resolve('accounts', '/apis/v/tokens/' + b.id),
                method: 'GET',
                json: true,
                auth: {
                    bearer: b.access_token
                }
            }, function (e, r, b) {
                if (e) {
                    return done(e);
                }
                r.statusCode.should.equal(200);
                should.exist(b);
                should.exist(b.id);
                should.exist(b.user);
                should.exist(b.client);
                should.exist(b.access);
                should.exist(b.refresh);
                should.exist(b.created);
                should.exist(b.accessible);
                should.exist(b.refreshable);
                should.exist(b.has);
                done();
            });
        });
    });
});
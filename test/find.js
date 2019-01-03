var log = require('logger')('service-token:test:find');
var should = require('should');
var request = require('request');
var pot = require('pot');
var mongoose = require('mongoose');
var errors = require('errors');

describe('GET /clients', function () {
  var user;
  var accessToken;
  var client;
  var custom;
  before(function (done) {
    pot.client(function (err, c) {
      if (err) {
        return done(err);
      }
      client = c;
      request({
        uri: pot.resolve('accounts', '/apis/v/users'),
        method: 'POST',
        headers: {
          'X-Captcha': 'dummy'
        },
        json: {
          alias: 'user',
          email: 'user@serandives.com',
          password: '1@2.Com',
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
          headers: {
            'X-Captcha': 'dummy'
          },
          form: {
            client_id: client.serandivesId,
            grant_type: 'password',
            username: 'user@serandives.com',
            password: '1@2.Com',
            redirect_uri: pot.resolve('accounts', '/auth')
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
              name: 'custom',
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
            b.name.should.equal('custom');
            b.to.length.should.equal(1);
            b.to[0].should.equal('http://test.serandives.com/dummy');
            custom = b;
            done();
          });
        });
      });
    });
  });

  it('GET /clients/:id unauthorized', function (done) {
    request({
      uri: pot.resolve('accounts', '/apis/v/clients/' + custom.id),
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

  it('GET /clients/:id', function (done) {
    request({
      uri: pot.resolve('accounts', '/apis/v/clients/' + custom.id),
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
      b.id.should.equal(custom.id);
      b.name.should.equal('custom');
      done();
    });
  });
});
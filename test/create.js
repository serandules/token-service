var log = require('logger')('service-token:test:create');
var errors = require('errors');
var should = require('should');
var request = require('request');
var pot = require('pot');

describe('POST /tokens', function () {
  var client;
  before(function (done) {
    pot.client(function (err, c) {
      if (err) return done(err);
      client = c;
      done();
    });
  });

  it('with no media type', function (done) {
    request({
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      json: true,
      auth: {
        bearer: client.users[0].token
      }
    }, function (e, r, b) {
      if (e) {
        return done(e);
      }
      r.statusCode.should.equal(errors.unsupportedMedia().status);
      should.exist(b);
      should.exist(b.code);
      should.exist(b.message);
      b.code.should.equal(errors.unsupportedMedia().data.code);
      done();
    });
  });

  it('with unsupported media type', function (done) {
    request({
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      headers: {
        'Content-Type': 'application/xml'
      },
      json: true,
      auth: {
        bearer: client.users[0].token
      }
    }, function (e, r, b) {
      if (e) {
        return done(e);
      }
      r.statusCode.should.equal(errors.unsupportedMedia().status);
      should.exist(b);
      should.exist(b.code);
      should.exist(b.message);
      b.code.should.equal(errors.unsupportedMedia().data.code);
      done();
    });
  });

  it('with unsupported grant type', function (done) {
    request({
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      form: {
        grant_type: 'custom'
      },
      json: true,
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
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      headers: {
        'X-Captcha': 'dummy'
      },
      form: {
        grant_type: 'password'
      },
      json: true,
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
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      headers: {
        'X-Captcha': 'dummy'
      },
      form: {
        grant_type: 'password',
        username: 'user0@serandives.com'
      },
      json: true,
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
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      headers: {
        'X-Captcha': 'dummy'
      },
      form: {
        grant_type: 'password',
        username: 'user0@serandives.com',
        password: '123456'
      },
      json: true
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
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      headers: {
        'X-Captcha': 'dummy'
      },
      form: {
        client_id: client.serandivesId,
        grant_type: 'password',
        username: 'user0@serandives.com',
        password: '123456',
        redirect_uri: pot.resolve('accounts', '/auth')
      },
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

  it('password grant type with valid password', function (done) {
    request({
      uri: pot.resolve('apis', '/v/tokens'),
      method: 'POST',
      headers: {
        'X-Captcha': 'dummy'
      },
      form: {
        client_id: client.serandivesId,
        grant_type: 'password',
        username: 'user0@serandives.com',
        password: '1@2.Com',
        redirect_uri: pot.resolve('accounts', '/auth')
      },
      json: true
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
        uri: pot.resolve('apis', '/v/tokens/' + b.id),
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
        should.exist(b.createdAt);
        should.exist(b.accessible);
        should.exist(b.refreshable);
        done();
      });
    });
  });

  it('password grant with a blocked user', function (done) {
    var usr = {
      email: 'unconfirmed@serandives.com',
      password: '1@2.Com',
      username: 'unconfirmed-user'
    };
    request({
      uri: pot.resolve('apis', '/v/users'),
      method: 'POST',
      headers: {
        'X-Captcha': 'dummy'
      },
      json: usr
    }, function (e, r, user) {
      if (e) {
        return done(e);
      }
      if (r.statusCode !== 201) {
        return done(new Error(r.statusCode));
      }
      should.exist(user.id);
      should.exist(user.email);
      user.email.should.equal(usr.email);
      request({
        uri: pot.resolve('apis', '/v/tokens'),
        method: 'POST',
        headers: {
          'X-Captcha': 'dummy'
        },
        form: {
          client_id: client.serandivesId,
          grant_type: 'password',
          username: 'unconfirmed@serandives.com',
          password: '1@2.Com',
          redirect_uri: pot.resolve('accounts', '/auth')
        },
        json: true
      }, function (e, r, b) {
        if (e) {
          return done(e);
        }
        r.statusCode.should.equal(errors.forbidden().status);
        should.exist(b);
        should.exist(b.code);
        should.exist(b.message);
        b.code.should.equal(errors.forbidden().data.code);
        done();
      });
    });
  });
});

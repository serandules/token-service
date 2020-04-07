var log = require('logger')('service-tokens:validators');
var nconf = require('nconf');
var async = require('async');
var request = require('request');
var crypto = require('crypto');

var errors = require('errors');
var serandi = require('serandi');
var utils = require('utils');
var Tokens = require('model-tokens');
var Users = require('model-users');
var Clients = require('model-clients');
var mongutils = require('mongutils');
var model = require('model');

var REDIRECT_URI = utils.resolve('accounts:///auth/oauth');

var MIN_ACCESSIBILITY = 20 * 1000;

exports.MIN_ACCESSIBILITY = MIN_ACCESSIBILITY;

var context = {
  domain: {},
  facebook: {
    id: nconf.get('FACEBOOK_ID'),
    secret: nconf.get('FACEBOOK_SECRET'),
    token: nconf.get('FACEBOOK_TOKEN_URI'),
    profile: nconf.get('FACEBOOK_PROFILE_URI')
  }
};

var domain = utils.domain();

Clients.findOne({
  name: domain
}, function (err, client) {
  if (err) {
    throw err;
  }
  if (!client) {
    throw new Error('no domain client found in the database');
  }
  var domain = context.domain;
  domain.id = client.id;
  domain.secret = client.secret;
});

var passwordGrant = function (req, res, next) {
  var data = req.body;
  var username = data.username;
  if (!username) {
    return next(errors.unprocessableEntity('\'username\' needs to be specified'));
  }
  var password = data.password;
  if (!password) {
    return next(errors.unprocessableEntity('\'password\' needs to be specified'));
  }
  var clientId = data.client_id;
  if (!clientId) {
    return next(errors.unprocessableEntity('\'client_id\' needs to be specified'));
  }
  var location = data.redirect_uri;
  if (!location) {
    return next(errors.unprocessableEntity('\'redirect_uri\' needs to be specified'));
  }
  Users.findOne({
    email: req.body.username
  }).populate('tokens').exec(function (err, user) {
    if (err) {
      log.error('users:find-one', err);
      return next(errors.serverError());
    }
    if (!user) {
      return next(errors.unauthorized());
    }
    if (user.status !== 'registered') {
      return next(errors.forbidden());
    }
    Users.auth(user, req.body.password, function (err, auth) {
      if (err) {
        log.error('users:auth', err);
        return next(errors.serverError());
      }
      if (!auth) {
        return next(errors.unauthorized());
      }
      req.user = user;
      req.body = {
        client: clientId,
        location: location
      };
      next();
    });
  });
};

var sendRefreshToken = function (req, res, done) {
  Tokens.findOne({
    refresh: req.body.refresh_token
  }).populate('client')
    .populate('user')
    .exec(function (err, token) {
      if (err) {
        log.error('tokens:find-one', err);
        return done(errors.serverError());
      }
      if (!token) {
        return done(errors.unauthorized());
      }
      if (token.user && token.user.status !== 'registered') {
        return done(errors.forbidden());
      }
      var expin = token.refreshability();
      if (expin === 0) {
        return done(errors.unauthorized());
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
          log.error('tokens:refresh', err);
          return done(errors.serverError());
        }
        Tokens.findOne({
          _id: token.id
        }, function (err, token) {
          if (err) {
            log.error('tokens:find-one', err);
            return done(errors.serverError());
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

var refreshGrant = function (req, res, next) {
  var data = req.body;
  var refreshToken = data.refresh_token;
  if (!refreshToken) {
    return next(errors.unprocessableEntity('\'refresh_token\' needs to be specified'));
  }
  async.retry({times: 4, interval: 500}, function (tried) {
    sendRefreshToken(req, res, tried)
  }, function (err) {
    if (err) {
      next(errors.conflict());
    }
  });
};

var upperCase = function () {
  var seeds = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return seeds.charAt(Math.floor(Math.random() * seeds.length))
};

var lowerCase = function () {
  var seeds = 'abcdefghijklmnopqrstuvwxyz';
  return seeds.charAt(Math.floor(Math.random() * seeds.length))
};

var number = function () {
  var seeds = '0123456789';
  return seeds.charAt(Math.floor(Math.random() * seeds.length))
};

var symbol = function () {
  var seeds = '!@#$%^&*()_+?';
  return seeds.charAt(Math.floor(Math.random() * seeds.length))
}

var randomPassword = function (done) {
  crypto.randomBytes(48, function (err, buf) {
    if (err) {
      return done(err);
    }
    done(null, buf.toString('hex') + upperCase() + symbol() + number() + lowerCase());
  });
};

var facebookGrant = function (req, res, next) {
  var data = req.body;
  var code = data.code;
  if (!code) {
    return next(errors.unprocessableEntity('\'code\' needs to be specified'));
  }
  var clientId = data.client_id;
  if (!clientId) {
    return next(errors.unprocessableEntity('\'client_id\' needs to be specified'));
  }
  var location = data.redirect_uri;
  if (!location) {
    return next(errors.unprocessableEntity('\'redirect_uri\' needs to be specified'));
  }
  var userExists = function (user, next) {
    if (user.status !== 'registered') {
      return next(errors.forbidden());
    }
    req.user = user;
    req.body = {
      client: clientId,
      location: location
    };
    next();
  };
  var domain = context.domain;
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
      log.error('facebook:grant', err);
      return next(errors.serverError());
    }
    if (response.statusCode !== 200) {
      return next(errors.unauthorized());
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
        log.error('facebook:token', err);
        return next(errors.serverError());
      }
      if (response.statusCode !== 200) {
        return next(errors.unauthorized());
      }
      var email = body.email;
      if (!email) {
        log.error('facebook:no-email', err);
        return next(errors.serverError());
      }
      Users.findOne({
        email: email
      }).populate('tokens').exec(function (err, user) {
        if (err) {
          log.error('users:find-one', err);
          return next(errors.serverError());
        }
        if (user) {
          return userExists(user, next);
        }
        var username = data.username;
        if (!username) {
          return next(errors.unauthorized());
        }
        var name = body.first_name || '';
        name += name ? ' ' : '';
        name += body.last_name || '';
        randomPassword(function (err, pass) {
          if (err) {
            return done(err);
          }
          model.create({
            model: Users,
            data: {
              email: email,
              password: pass,
              username: username,
              name: name
            },
            overrides: {}
          }, function (err, user) {
            if (err) {
              if (err.code === mongutils.errors.DuplicateKey) {
                return next(errors.conflict());
              }
              log.error('users:create', err);
              return next(errors.serverError());
            }
            utils.workflow('model-users', function (err, workflow) {
              if (err) {
                return next(err);
              }
              var status = 'registered';
              var permit = workflow.permits[status];
              var usr = utils.json(user);
              utils.toPermissions(usr.id, permit, usr, function (err, permissions) {
                if (err) {
                  return next(err);
                }
                utils.toVisibility(usr.id, permit, usr, function (err, visibility) {
                  if (err) {
                    return next(err);
                  }
                  Users.findOneAndUpdate({_id: user.id}, {
                    status: status,
                    permissions: permissions,
                    visibility: visibility
                  }).exec(function (err) {
                    if (err) {
                      return next(err);
                    }
                    req.user = user;
                    req.body = {
                      client: domain.id,
                      location: location
                    };
                    next();
                  });
                });
              });
            });
          });
        });
      });
    });
  });
};

exports.grant = function (req, res, next) {
  var type = req.body.grant_type;
  if (type === 'password') {
    serandi.captcha(req, res, function (err) {
      if (err) {
        return next(err);
      }
      passwordGrant(req, res, next);
    });
    return;
  }
  if (type === 'refresh_token') {
    return refreshGrant(req, res, next);
  }
  if (type === 'facebook') {
    return facebookGrant(req, res, next);
  }
  next(errors.unprocessableEntity('Invalid grand type requested'));
};

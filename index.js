var log = require('logger')('token-service');
var bodyParser = require('body-parser');

var errors = require('errors');
var auth = require('auth');
var throttle = require('throttle');
var serandi = require('serandi');
var Clients = require('model-clients');
var Tokens = require('model-tokens');
var model = require('model');

var validators = require('./validators');

var MIN_ACCESSIBILITY = validators.MIN_ACCESSIBILITY;

var sendToken = function (req, res, next) {
  var clientId = req.body.client;
  Clients.findOne({
    _id: clientId
  }, function (err, client) {
    if (err) {
      log.error('clients:find-one', err);
      return next(errors.serverError());
    }
    if (!client) {
      return next(errors.unauthorized());
    }
    var location = req.body.location;
    var to = client.to;
    if (to.indexOf(location) === -1) {
      return next(errors.forbidden());
    }
    Tokens.findOne({
      user: req.user.id,
      client: client.id
    }, function (err, token) {
      if (err) {
        log.error('tokens:find-one', err);
        return next(errors.serverError());
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
      model.create(req.ctx, function (err, token) {
        if (err) {
          log.error('tokens:create', err);
          return next(errors.serverError());
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

module.exports = function (router, done) {
  router.use(serandi.ctx);
  router.use(auth({
    GET: [
      '^\/$',
      '^\/.*'
    ],
    POST: [
      '^\/$',
      '^\/.*'
    ]
  }));
  router.use(throttle.apis('tokens'));
  router.use(bodyParser.json());
  router.use(bodyParser.urlencoded({extended: true}));

  router.get('/:id',
    serandi.findOne(Tokens),
    function (req, res, next) {
      model.findOne(req.ctx, function (err, token) {
        if (err) {
          return next(err);
        }
        res.send({
          id: token.id,
          user: req.user.id,
          client: token.client.id,
          access: token.access,
          refresh: token.refresh,
          createdAt: token.createdAt,
          accessible: token.accessible,
          refreshable: token.refreshable
        });
      });
    });

  router.post('/',
    serandi.urlencoded,
    validators.grant,
    serandi.create(Tokens),
    function (req, res, next) {
      sendToken(req, res, next);
    });

  router.delete('/:id',
    serandi.remove(Tokens),
    function (req, res, next) {
    model.remove(req.ctx, function (err) {
      if (err) {
        return next(err);
      }
      res.status(204).end();
    });
  });

  done();
};
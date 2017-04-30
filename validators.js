var errors = require('errors');
var validators = require('validators');

var passwordGrant = function (res, data, next) {
    var username = data.username;
    if (!username) {
        return res.pond(errors.unprocessableEntiy('\'username\' needs to be specified'));
    }
    var password = data.password;
    if (!password) {
        return res.pond(errors.unprocessableEntiy('\'password\' needs to be specified'));
    }
    var client_id = data.client_id;
    if (!client_id) {
        return res.pond(errors.unprocessableEntiy('\'client_id\' needs to be specified'));
    }
    next();
};

var refreshGrant = function (res, data, next) {
    var refreshToken = data.refresh_token;
    if (!refreshToken) {
        return res.pond(errors.unprocessableEntiy('\'refresh_token\' needs to be specified'));
    }
    next();
};

var facebookGrant = function (res, data, next) {
    var code = data.code;
    if (!code) {
        return res.pond(errors.unprocessableEntiy('\'code\' needs to be specified'));
    }
    next();
};

exports.create = function (req, res, next) {
    validators.json(req, res, function (err) {
        if (err) {
            return next(err);
        }
        var data = req.body;
        var grantType = data.grant_type;
        if (!grantType) {
            return res.pond(errors.unprocessableEntiy('\'grant_type\' needs to be specified'));
        }
        if (['password', 'facebook', 'refresh_token'].indexOf(grantType) === -1) {
            return res.pond(errors.unprocessableEntiy('\'grand_type\' contains an invalid value'));

        }
        if (grantType === 'password') {
            return passwordGrant(res, data, next);
        }
        if (grantType === 'refresh_token') {
            return refreshGrant(res, data, next)
        }
        if (grantType === 'facebook') {
            return facebookGrant(res, data, next)
        }
        next();
    });
};
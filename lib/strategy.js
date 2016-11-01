var passport = require('passport-strategy')
var url = require('url');
var util = require('util');
var utils = require('./utils');
var debug = require('debug')('passport-sms-public');
var _ = require('lodash');
var SMS_TYPE = "LOGIN";
var SUC_RESULT = { "result": "OK" };

function SmsPublicStrategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = undefined;
    }
    options = options || {};

    if (!verify) {
        throw new TypeError('SmsPublicStrategy requires a verify callback');
    }

    if (!options.verifyMobileCode) {
        throw new TypeError('SmsPublicStrategy requires a verifyMobileCode option');
    }

    if (!options.sendSmsCode) {
        throw new TypeError('SmsPublicStrategy requires a sendSmsCode option');
    }

    passport.Strategy.call(this);
    this.name = 'sms-public';
    this._verify = verify;
    this.verifyMobileCode = options.verifyMobileCode;
    this.sendSmsCode = options.sendSmsCode;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(SmsPublicStrategy, passport.Strategy);


SmsPublicStrategy.prototype.authenticate = function(req, options) {
    options = options || {};

    var self = this;

    function verified(err, user, info) {
        if (err) {
            return self.error(err);
        }
        if (!user) {
            return self.fail(info);
        }
        self.success(user, info);
    }

    function verifyResult(accessToken, refreshToken, params, profile, verified) {
        try {
            var arity = self._verify.length;
            if (self._passReqToCallback) {
                if (arity === 6) {
                    self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                    self._verify(req, accessToken, refreshToken, profile, verified);
                }
            } else {
                if (arity === 5) {
                    self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                    self._verify(accessToken, refreshToken, profile, verified);
                }
            }
        } catch (ex) {
            self.error(ex);
        }
    }

    var params = {};
    if (req.query && req.query.mobile && !req.query.code) {
        var mobile = req.query.mobile;
        //生成验证码 4位
        var code = Math.round(Math.random() * 10000);
        var mobileparams = { mobile: mobile, type: SMS_TYPE };
        var mobileAndCodeparams = { mobile: mobile, code: code, type: SMS_TYPE };
        //发送短信验证码  查询是否已发送过的逻辑全在sendSmsCode里面
        self.sendSmsCode(mobileparams,
            function(err, result) {
                if (err) return self.error(err);
                //response ok
                self.success(null,null);
            }
        );
    } else if (req.query && req.query.mobile && req.query.code) {
        var code = req.query.code;
        var mobile = req.query.mobile;
        var mobileAndCodeparams = { mobile: mobile, code: code, type: SMS_TYPE };
        var profile = {
                id: mobile,
                openid: mobile
            }
        //查询发送信息
        self.verifyMobileCode(mobileAndCodeparams, function(err, result) {
            if (err) return self.error(err);
            verifyResult(mobile, mobile, {}, profile, verified);
        });
    } else {
        self.error(new Error("请指定mobile 和 code 参数"));
    }
};



module.exports = SmsPublicStrategy;

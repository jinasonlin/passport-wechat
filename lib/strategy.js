'use strict';
/*
 * passport-wechat
 *
 * author: Jim Lin
 */

var util = require('util');
var passport = require('passport-strategy');
var OAuth = require('wechat-oauth');
var uid = require('uid2');
var extend = require('util')._extend;
var debug = require('debug')('passport-wechat');

function WechatStrategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = undefined;
  }

  options = options || {};

  if (!verify) {
    throw new TypeError('WeChatStrategy required a verify callback');
  }

  if (typeof verify !== 'function') {
    throw new TypeError('_verify must be function');
  }

  if (!options.appid) {
    throw new TypeError('WechatStrategy requires a appid option');
  }

  if (!options.appsecret) {
    throw new TypeError('WechatStrategy requires a appsecret option');
  }

  passport.Strategy.call(this, options, verify);

  this.name = options.name || 'wechat'; // 用于生成多个passport中间件名称，可用于限制授权类型
  this._isRename = options.name ? true : false;
  if (this.name && !~['wechat', 'wechatWebsite'].indexOf(this.name)) {
    throw new TypeError('WechatStrategy name error, now only wechat & wechatWebsite');
  }
  // this._client = options.client || 'wechat'; // 客户端授权／网站授权
  // if (this._client && !~['wechat', 'wechatWebsite'].indexOf(this._client)) {
  //   throw new TypeError('WechatStrategy client error, now only wechat & wechatWebsite');
  // }
  this._verify = verify;
  if (options.getToken && options.saveToken) {
    this._oauth = new OAuth(options.appid, options.appsecret, options.getToken, options.saveToken);
  } else {
    this._oauth = new OAuth(options.appid, options.appsecret);
  }
  this._callbackURL = options.callbackURL;
  this._key = options.sessionKey || '__wechat:session';
  this._lang = options.lang || 'zh_CN';
  this._requireState = options.requireState;
  this._scope = options.scope || 'snsapi_userinfo';
  // if (this._scope && !~['snsapi_base', 'snsapi_userinfo','snsapi_login'].indexOf(this._scope)) {
  //   throw new TypeError('WechatStrategy scope error');
  // }
  this._passReqToCallback = options.passReqToCallback;

  this._direct = options.direct; // 授权地址跳转可能存在延迟
  this._force = options.force; // 测试参数，用于在snsapi_base情况下，获取用户更多信息
}

/**
 * Inherit from 'passort.Strategy'
 */
util.inherits(WechatStrategy, passport.Strategy);

WechatStrategy.prototype.authenticate = function (req, options) {
  if (!req._passport) {
    return this.error(new Error('passport.initialize() middleware not in use'));
  }

  var self = this;
  options = options || {};

  // 获取code，用户禁止授权
  if (req.query && req.query.state && !req.query.code) {
    debug('Bad request -> \n[%s]', req.url);
    return self.fail(401);
  }

  // 获取code授权成功
  if (req.query && req.query.code) {
    var code = req.query.code;

    debug('Process wechat callback -> \n %s', req.url);

    // 增加并开启state的验证，提高安全性
    if (this._requireState) {
      if (!req.session) {
        return this.error(new Error('WechatStrategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      if (!req.session[key]) {
        return this.fail({message: 'Unable to verify authorization request state.'}, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({message: 'Unable to verify authorization request state.'}, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({message: 'Invalid authorization request state.'}, 403);
      }
    }

    self._oauth.getAccessToken(code, function (err, response) {
      // 校验完成信息
      function verified(err, profile, info) {
        if (err) {
          return self.error(err);
        }
        if (!profile) {
          return self.fail(info);
        }
        return self.success(profile, info);
      }

      if (err) {
        return self.error(err);
      }

      var params = response.data;

      if (~params.scope.indexOf('snsapi_base')  && !self._force) {
        var profile = {
          openid: params.openid,
          unionid: params.unionid
        };
        try {
          if (self._passReqToCallback) {
            self._verify(req, params.access_token, params.refresh_token, profile, verified);
          } else {
            self._verify(params.access_token, params.refresh_token, profile, verified);
          }
        } catch (ex) {
          return self.error(ex);
        }
      } else {
        var lang = self._lang || options.lang;
        self._oauth.getUser({
          openid: params.openid,
          lang: lang
        }, function (err, profile) {
          if (err) {
            debug('return wechat user profile ->', err.message);
            return self.error(err);
          }

          debug('return wechat user profile -> \n %s', JSON.stringify(profile, null, ' '));

          var _profile =  extend(profile, params);

          try {
            if (self._passReqToCallback) {
              self._verify(req, params.access_token, params.refresh_token, _profile, verified);
            } else {
              self._verify(params.access_token, params.refresh_token, _profile, verified);
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    });
  } else {
    // 使用前置options参数
    var callbackURL = options.callbackURL || this._callbackURL;
    var scope = options.scope || this._scope;
    // var scope = this._scope;
    // if (!!~['snsapi_base', 'snsapi_userinfo','snsapi_login'].indexOf(options.scope)) {
    //   scope = options.scope;
    // }
    // 生成state验证信息，默认提供一个'STATE'，用于用户禁止授权时的特殊判断
    var state = 'STATE';
    if (this._requireState) {
      if (!req.session) {
        return this.error(new Error('WeChatStrategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      state = uid(24);
      if (!req.session[key]) {
        req.session[key] = {};
      }
      req.session[key].state = state;
    }

    var method = this.getAuthorizeMethodName(options.client);
    var location = this._oauth[method](callbackURL, state, scope);
    debug('redirect authorizeURL -> \n%s', location);
    if (!this.direct) {
      setTimeout(function () {
        self.redirect(location, 302);
      }, 200);
    } else {
      this.redirect(location, 302);
    }
  }
};

WechatStrategy.prototype.getAuthorizeMethodName = function (client) {
  var _case;
  if (this._isRename) {
    _case = this.name;
  } else {
    _case = client;
  }

  if (_case === 'wechatWebsite') {
    return 'getAuthorizeURLForWebsite';
  } else {
    return 'getAuthorizeURL';
  }
};

module.exports = WechatStrategy;

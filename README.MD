# passport-wechat

##支持功能

* 微信公众账号
* 微信网站登陆
    
## 使用
#### Configure  Strategy

```js

 passport.use(new WechatStrategy({
        appID: {APPID},
        name: {默认为wechat,支持wechatWebsite.提供公众号和网站的登录}
        appSecret: {APPSECRET},
        callbackURL: {CALLBACKURL},
        scope: {snsapi_userinfo|snsapi_base},
        state: {STATE}
      },
      function(accessToken, refreshToken, profile, done) {
        return done(err,profile);
      }
));

```

#### Authenticate Requests

```js
  router.get('/auth/wechat', passport.authenticate('wechat', options));
```
`options` - Optional. Can include the following:
* `lang` - set language
* `scope` - Override scope for this specific API call
* `callbackURL` - Override callbackURL for this specific API call
* `client` - set like strategy name

#### Authentication Callback

```js
  router.get('/auth/wechat/callback', passport.authenticate('wechat', {
    failureRedirect: '/auth/fail',
    successReturnToOrRedirect: '/'
  }));
```

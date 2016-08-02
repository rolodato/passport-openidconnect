/**
 * Module dependencies.
 */
var passport = require('passport')
  , url = require('url')
  , querystring = require('querystring')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , setup = require('./setup')
  , InternalOAuthError = require('./errors/internaloautherror')
  , jwt = require('jsonwebtoken')
  , jwksClient = require('jwks-rsa')
  , SessionStore = require('passport-oauth2').NullStore;

/**
 * `Strategy` constructor.
 *
 * The OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;

  // TODO: What's the recommended field name for OpenID Connect?
  this._identifierField = options.identifierField || 'openid_identifier';
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

  this._configurers = [];

  if (options.authorizationURL && options.tokenURL) {
    // This OpenID Connect strategy is configured to work with a specific
    // provider.  Override the discovery process with pre-configured endpoints.
    this.configure(function(identifier, done) {
      return done(null, {
        authorizationURL: options.authorizationURL,
        tokenURL: options.tokenURL,
        userInfoURL: options.userInfoURL,
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL
      });
    });
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.normalizeProfile = function (json) {
  var profile = {};
  profile.id = json.sub;
  // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
  // "sub" key was named "user_id".  Many providers still use the old
  // key, so fallback to that.
  if (!profile.id) {
    profile.id = json.user_id;
  }
  profile.displayName = json.name;
  profile.name = {
    familyName: json.family_name,
    givenName: json.given_name,
    middleName: json.middle_name
  };
  if (json.picture) {
    profile.photos = [
      {
        value: json.picture
      }
    ];
  }
  profile._raw = JSON.stringify(json);
  profile._json = json;
  return profile;
};

/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  if (req.body && req.body.id_token) {
    // response_mode=form_post authentication response
    this.configure(null, function (err, config) {
      if (err) {
        return self.error(err);
      }
      var sessionKey = options.sessionKey || ('oauth2:' + url.parse(config.authorizationURL).hostname);
      var store = options.store || new SessionStore({ key: sessionKey });
      function getTokenKey(cb) {
        if (config.clientSecret && !config.jwksURL) {
          cb(null, config.clientSecret, 'HS256');
        } else if (config.jwksURI) {
          var client = jwksClient({
            cache: true,
            rateLimit: true,
            jwksUri: config.jwksURI
          });
          var decoded = jwt.decoded(req.body.id_token, { complete: true });
          if (decoded && decoded.header.kid) {
            client.getSigningKey(decoded.header.kid, function (err, key) {
              cb(err, key.publicKey || key.rsaPublicKey, 'RS256');
            });
          } else if (!decoded) {
            cb(new Error('Malformed ID token: ' + req.body.id_token));
          } else {
            cb(new Error('Expected asymmetrically signed token but no key ID found in JWT'));
          }
        } else {
          cb(new Error('No client secret or JWKS URL configured to verify JWTs'));
        }
      }
      getTokenKey(function (err, key, alg) {
        if (err) { return self.error(err); }
        jwt.verify(req.body.id_token, key, {
          algorithm: alg,
          issuer: config.issuer
        }, function (err, decoded) {
          if (err) {
            return self.error(err);
          }
          store.verify(req, req.body.state, function (err, isValid, msg) {
            if (err) { return self.error(err); }
            if (!isValid) {
              return self.error(new Error('Invalid state parameter'));
            }
            if (decoded.nonce !== req.body.nonce) {
              return self.error(new Error('Nonce mismatch between ID token and authorization server response'));
            }
            self._shouldLoadUserProfile(decoded.iss, decoded.sub || decoded.user_id, function (err, load) {
              if (err) { return self.error(err); }
              if (load) {
                try {
                  onProfileLoaded(self.normalizeProfile(decoded));
                } catch (ex) {
                  return self.error(ex);
                }
              } else {
                onProfileLoaded();
              }

              function onProfileLoaded(profile) {
                function verified(err, user, info) {
                  if (err) { return self.error(err); }
                  if (!user) { return self.fail(info); }
                  self.success(user, info);
                }
                var iss = decoded.iss;
                var sub = decoded.sub || decoded.user_id;
                if (self._passReqToCallback) {
                  self._verify(req, iss, sub, profile, req.body.id_token, verified);
                } else {
                  self._verify(iss, sub, profile, req.body.id_token, verified);
                }
              }
            });
          });
        });
      });
    });

  } else if (req.query && req.query.code) {
    var code = req.query.code;

    this.configure(null, function(err, config) {
      if (err) { return self.error(err); }

      var oauth2 = new OAuth2(config.clientID,  config.clientSecret,
                              '', config.authorizationURL, config.tokenURL);

      var callbackURL = options.callbackURL || config.callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
      }

      oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

        var idToken = params['id_token'];
        if (!idToken) { return self.error(new Error('ID Token not present in token response')); }

        var jwtClaims = jwt.decode(idToken);
        if (!jwtClaims) {
          return self.error(new Error('Malformed ID token: ' + idToken));
        }

        // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
        // "sub" claim was named "user_id".  Many providers still issue the
        // claim under the old field, so fallback to that.
        var sub = jwtClaims.sub || jwtClaims.user_id;
        var iss = jwtClaims.iss;

        // TODO: Ensure claims are validated per:
        //       http://openid.net/specs/openid-connect-basic-1_0.html#id_token

        self._shouldLoadUserProfile(iss, sub, function(err, load) {
          if (err) { return self.error(err); }

          if (load) {
            var parsed = url.parse(config.userInfoURL, true);
            parsed.query['schema'] = 'openid';
            delete parsed.search;
            var userInfoURL = url.format(parsed);

            // NOTE: We are calling node-oauth's internal `_request` function (as
            //       opposed to `get`) in order to send the access token in the
            //       `Authorization` header rather than as a query parameter.
            //
            //       Additionally, the master branch of node-oauth (as of
            //       2013-02-16) will include the access token in *both* headers
            //       and query parameters, which is a violation of the spec.
            //       Setting the fifth argument of `_request` to `null` works
            //       around this issue.  I've noted this in comments here:
            //       https://github.com/ciaranj/node-oauth/issues/117

            //oauth2.get(userInfoURL, accessToken, function (err, body, res) {
            oauth2._request("GET", userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, function (err, body, res) {
              if (err) { return self.error(new InternalOAuthError('failed to fetch user profile', err)); }
              try {
                onProfileLoaded(self.normalizeProfile(JSON.parse(body)));
              } catch(ex) {
                return self.error(ex);
              }
            });
          } else {
            onProfileLoaded();
          }

          function onProfileLoaded(profile) {
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              self.success(user, info);
            }

            var arity;
            if (self._passReqToCallback) {
              arity = self._verify.length;
              if (arity == 9) {
                self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity == 8) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity == 7) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity == 5) {
                self._verify(req, iss, sub, profile, verified);
              } else { // arity == 4
                self._verify(req, iss, sub, verified);
              }
            } else {
              arity = self._verify.length;
              if (arity == 8) {
                self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity == 7) {
                self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity == 6) {
                self._verify(iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity == 4) {
                self._verify(iss, sub, profile, verified);
              } else { // arity == 3
                self._verify(iss, sub, verified);
              }
            }
          }

        });
      });
    });
  } else {
    // The request being authenticated is initiating OpenID Connect
    // authentication.  Prior to redirecting to the provider, configuration will
    // be loaded.  The configuration is typically either pre-configured or
    // discovered dynamically.  When using dynamic discovery, a user supplies
    // their identifer as input.

    var identifier;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    }

    this.configure(identifier, function(err, config) {
      if (err) { return self.error(err); }

      var callbackURL = options.callbackURL || config.callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
      }

      var params = {};
      params['response_type'] = 'code';
      params['client_id'] = config.clientID;
      params['redirect_uri'] = callbackURL;
      var scope = options.scope || self._scope;
      if (Array.isArray(scope)) { scope = scope.join(self._scopeSeparator); }
      if (scope) {
        params.scope = 'openid' + self._scopeSeparator + scope;
      } else {
        params.scope = 'openid';
      }
      // TODO: Add support for automatically generating a random state for verification.
      // TODO: Make state optional, if `config` disables it and supplies an alternative
      //       session key.
      //var state = options.state;
      //if (state) { params.state = state; }

      params.state = utils.uid(16);

      // TODO: Implement support for standard OpenID Connect params (display, prompt, etc.)

      var location = config.authorizationURL + '?' + querystring.stringify(params);
      self.redirect(location);
    });
  }
};

/**
 * Register a function used to configure the strategy.
 *
 * OpenID Connect is an identity layer on top of OAuth 2.0.  OAuth 2.0 requires
 * knowledge of certain endpoints (authorization, token, etc.) as well as a
 * client identifier (and corresponding secret) registered at the authorization
 * server.
 *
 * Configuration functions are responsible for loading this information.  This
 * is typically done via one of two popular mechanisms:
 *
 *   - The configuration is known ahead of time, and pre-configured via options
 *     to the strategy.
 *   - The configuration is dynamically loaded, using optional discovery and
 *     registration specifications.  (Note: Providers are not required to
 *     implement support for dynamic discovery and registration.  As such, there
 *     is no guarantee that this will result in successfully initiating OpenID
 *     Connect authentication.)
 *
 * @param {Function} fn
 * @api public
 */
Strategy.prototype.configure = function(identifier, done) {
  if (typeof identifier === 'function') {
    return this._configurers.push(identifier);
  }

  // private implementation that traverses the chain of configurers, attempting
  // to load configuration
  var stack = this._configurers;
  (function pass(i, err, config) {
    // an error or configuration was obtained, done
    if (err || config) { return done(err, config); }

    var layer = stack[i];
    if (!layer) {
      // Strategy-specific functions did not result in obtaining configuration
      // details.  Proceed to protocol-defined mechanisms in an attempt
      // to discover the provider's configuration.
      return setup(identifier, done);
    }

    try {
      layer(identifier, function(e, c) { pass(i + 1, e, c); } );
    } catch (ex) {
      return done(ex);
    }
  })(0);
};


/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return {};
};

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(issuer, subject, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return done(null, true); }
      return done(null, false);
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
    if (!skip) { return done(null, true); }
    return done(null, false);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

// Generated by CoffeeScript 1.6.3
(function() {
  var Crypto, base32tohex, computeOTP, dec2hex, extractYubicoIdentity, generateBase32Code, hex2dec, https, leftpad, verifyYubicode, _;

  https = require('https');

  Crypto = (require('cryptojs')).Crypto;

  _ = require('lodash');

  module.exports = function(app) {
    this.users = [
      {
        user: "admin",
        password: "password",
        yubico_identity: "ccccccbggtft",
        googleCode: "JBSWY3DPEHPK3PXP"
      }, {
        user: "schmuck",
        password: "password",
        yubico_identity: "fifjgjgkhcha",
        googleCode: "JBSWY3DPEHPK3PXX"
      }
    ];
    app.get('/', function(req, res) {
      return res.render('index', {
        title: 'Demo OWASP Multifacteurs'
      });
    });
    app.get('/register', function(req, res) {
      return res.render('register', {
        title: 'Demo OWASP Multifacteurs'
      });
    });
    app.post('/do_register', function(req, res) {
      var code, user;
      code = generateBase32Code();
      user = {
        user: req.body.user,
        password: req.body.password,
        yubico_identity: extractYubicoIdentity(req.body.yubicode),
        googleCode: code
      };
      this.users.push(user);
      return res.render('do_register', {
        title: 'Demo OWASP Multifacteurs',
        user: user.user,
        code: user.googleCode
      });
    });
    return app.post('/verify', function(req, res) {
      var identity, key, otp, user, _ref;
      user = _.find(this.users, function(user) {
        return user.user === req.body.user;
      });
      if (user && user.password === req.body.password) {
        key = req.body.key;
        if ((32 <= (_ref = key.length) && _ref <= 48)) {
          identity = extractYubicoIdentity(key);
          if (user.yubico_identity === identity) {
            return verifyYubicode(key, user, res);
          } else {
            return res.render('fail', {
              title: 'Demo OWASP Multifacteurs',
              reason: 'Identité inconnue.'
            });
          }
        } else {
          otp = computeOTP(user.googleCode);
          if (otp === key) {
            return res.render('authenticated', {
              title: 'Demo OWASP Multifacteurs',
              user: user.user
            });
          } else {
            return res.render('fail', {
              title: 'Demo OWASP Multifacteurs',
              reason: 'Mauvaise clé.'
            });
          }
        }
      } else {
        return res.render('fail', {
          title: 'Demo OWASP Multifacteurs',
          reason: 'Mauvais User/Pass'
        });
      }
    });
  };

  extractYubicoIdentity = function(code) {
    return code.slice(0, -32);
  };

  verifyYubicode = function(otp, user, response) {
    var clientId, nonce, req, secretKey;
    clientId = process.env['YUBIKEY_CLIENT'] || 1;
    secretKey = process.env['YUBIKEY_SECRET'];
    nonce = Crypto.util.bytesToHex(Crypto.util.randomBytes(20));
    req = https.get("https://api2.yubico.com/wsapi/2.0/verify?id=" + clientId + "&otp=" + otp + "&nonce=" + nonce, function(res) {
      var data;
      data = "";
      res.setEncoding('utf8');
      res.on('data', function(chunk) {
        return data = data + chunk;
      });
      return res.on('end', function() {
        var computedHash, hmac, key, line, lines, message, result, _i, _len, _ref;
        lines = data.split("\n");
        result = {};
        for (_i = 0, _len = lines.length; _i < _len; _i++) {
          line = lines[_i];
          line = line.split("=");
          result[line[0]] = (_ref = line[1]) != null ? _ref.replace(/^\s+|\s+$/g, '') : void 0;
        }
        result.h = result.h + "=";
        if (result.status === "OK") {
          if (result.nonce === nonce) {
            if (result.otp === otp) {
              if (clientId === 1 || !secretKey) {
                console.log("Warning: No hash configuration");
                return response.render('authenticated', {
                  title: 'Demo OWASP Multifacteurs',
                  user: user.user
                });
              } else {
                message = "nonce=" + result.nonce + "&otp=" + result.otp + "&sl=" + result.sl + "&status=" + result.status + "&t=" + result.t;
                key = Crypto.util.base64ToBytes(secretKey);
                hmac = Crypto.HMAC(Crypto.SHA1, message, key, null);
                computedHash = Crypto.util.hexToBytes(hmac);
                computedHash = Crypto.util.bytesToBase64(computedHash);
                if (result.h === computedHash) {
                  return response.render('authenticated', {
                    title: 'Demo OWASP Multifacteurs',
                    user: user.user
                  });
                } else {
                  return response.render('fail', {
                    title: 'Demo OWASP Multifacteurs',
                    reason: "Yubico a répondu avec un mauvais hash, imposteur?"
                  });
                }
              }
            } else {
              return response.render('fail', {
                title: 'Demo OWASP Multifacteurs',
                reason: "Yubico répondu avec différent OTP, copy paste?"
              });
            }
          } else {
            return response.render('fail', {
              title: 'Demo OWASP Multifacteurs',
              reason: "Yubico répondu avec un différent nonce, copy-paste?"
            });
          }
        } else {
          return response.render('fail', {
            title: 'Demo OWASP Multifacteurs',
            reason: "Yubico répond avec le statut: " + result.status + "."
          });
        }
      });
    });
    return req.on('error', function(e) {
      console.log('problem with request: ' + e.message);
      return response.render('fail', {
        title: 'Demo OWASP Multifacteurs',
        reason: 'Identité Yubico inconnue.'
      });
    });
  };

  generateBase32Code = function() {
    var base32chars, i, key, _i;
    base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    key = "";
    for (i = _i = 1; _i <= 16; i = ++_i) {
      key += base32chars.charAt(Math.floor(Math.random() * (base32chars.length - 1)));
    }
    return key;
  };

  dec2hex = function(s) {
    return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
  };

  hex2dec = function(s) {
    return parseInt(s, 16);
  };

  base32tohex = function(base32) {
    var base32chars, bits, char, chunk, hex, index, val, _i, _j, _len, _len1, _ref, _ref1;
    base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    bits = "";
    hex = "";
    _ref = base32.split('');
    for (index = _i = 0, _len = _ref.length; _i < _len; index = ++_i) {
      char = _ref[index];
      val = base32chars.indexOf(char.toUpperCase());
      bits += leftpad(val.toString(2), 5, '0');
    }
    _ref1 = bits.split('');
    for (index = _j = 0, _len1 = _ref1.length; _j < _len1; index = ++_j) {
      char = _ref1[index];
      if (index % 4 === 0 && index < bits.length - 1) {
        chunk = bits.substr(index, 4);
        hex = hex + parseInt(chunk, 2).toString(16);
      }
    }
    return hex;
  };

  leftpad = function(str, len, pad) {
    if (len + 1 >= str.length) {
      str = Array(len + 1 - str.length).join(pad) + str;
    }
    return str;
  };

  computeOTP = function(key) {
    var bytesKey, bytesTime, delay, hmac, offset, otp, seconds, time;
    delay = 30;
    key = base32tohex(key);
    seconds = Math.round(new Date().getTime() / 1000.0);
    time = leftpad(dec2hex(Math.floor(seconds / delay)), 16, '0');
    bytesTime = Crypto.util.hexToBytes(time);
    bytesKey = Crypto.util.hexToBytes(key);
    hmac = Crypto.HMAC(Crypto.SHA1, bytesTime, bytesKey, null);
    offset = hex2dec(hmac.slice(-1));
    otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + '';
    otp = otp.slice(-6);
    return otp;
  };

}).call(this);

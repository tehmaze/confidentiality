"use strict";

(function () {
  var globals = {}, cryptoAPI;

  if (typeof crypto !== 'undefined') {
    // Use the native WebCryptoAPI
    cryptoAPI = crypto;
  } else if (typeof module !== 'undefined' && typeof require === 'function') {
    // In node.js, use @trust/webcrypto
    cryptoAPI = require('@trust/webcrypto');
  } else {
    throw new Error('Platform does not support the WebCryptoAPI');
  }

  if (typeof window !== 'undefined') {
    globals = window;
  }

  function ensureArrayBuffer(data) {
    if (data instanceof ArrayBuffer) {
      return data;
    } else if (typeof data === 'string') {
      return Base64Binary.decodeArrayBuffer(data);
    } else if (ArrayBuffer.isView(data)) {
      return data.buffer;
    }
    throw new Error("Don't know how to convert " + Object.prototype.toString.call(data) + " to ArrayBuffer");
  }

  function ensureUint8Array(data) {
    return new Uint8Array(ensureArrayBuffer(data));
  }

  function concat() {
    var total = 0, i, args = Array.prototype.slice.call(arguments), l = args.length;
    for (i = 0; i < l; i++) {
      total += args[i].length;
    }

    var output = new Uint8Array(total), offset = 0;
    for (i = 0; i < l; i++) {
      output.set(args[i], offset);
      offset += args[i].length;
    }

    return output;
  }

  var Base64Binary = {
    _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    /* will return a  Uint8Array type */
    decodeArrayBuffer: function (input) {
      console.log('decodeArrayBuffer', input.constructor.name);
      var bytes = parseInt((input.length / 4) * 3);
      var ab = new ArrayBuffer(bytes);
      this.decode(input, ab);

      return ab;
    },

    removePaddingChars: function (input) {
      return input.replace(/=+$/, '');
    },

    decode: function (input, arrayBuffer) {
      //get last chars to see if are valid
      input = this.removePaddingChars(input);

      var bytes = parseInt((input.length / 4) * 3, 10);

      var uarray;
      var chr1, chr2, chr3;
      var enc1, enc2, enc3, enc4;
      var i = 0;
      var j = 0;

      if (arrayBuffer)
        uarray = new Uint8Array(arrayBuffer);
      else
        uarray = new Uint8Array(bytes);

      input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

      for (i = 0; i < bytes; i += 3) {
        //get the 3 octects in 4 ascii chars
        enc1 = this._keyStr.indexOf(input.charAt(j++));
        enc2 = this._keyStr.indexOf(input.charAt(j++));
        enc3 = this._keyStr.indexOf(input.charAt(j++));
        enc4 = this._keyStr.indexOf(input.charAt(j++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        uarray[i] = chr1;
        if (enc3 != 64) uarray[i + 1] = chr2;
        if (enc4 != 64) uarray[i + 2] = chr3;
      }

      return uarray;
    }
  };

  var Curve25519 = (function () {
    // Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
    // Public domain.
    //
    // Implementation derived from TweetNaCl version 20140427.
    // See for details: http://tweetnacl.cr.yp.to/

    var u64 = function (h, l) { this.hi = h | 0 >>> 0; this.lo = l | 0 >>> 0; };
    var gf = function (init) {
      var i, r = new Float64Array(16);
      if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
      return r;
    };

    var _0 = new Uint8Array(16);
    var _9 = new Uint8Array(32); _9[0] = 9;

    var gf0 = gf(),
      gf1 = gf([1]),
      _121665 = gf([0xdb41, 1]),
      D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
      D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
      X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
      Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
      I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

    function car25519(o) {
      var c;
      var i;
      for (i = 0; i < 16; i++) {
        o[i] += 65536;
        c = Math.floor(o[i] / 65536);
        o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
        o[i] -= (c * 65536);
      }
    }

    function sel25519(p, q, b) {
      var t, c = ~(b - 1);
      for (var i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
      }
    }

    function pack25519(o, n) {
      var i, j, b;
      var m = gf(), t = gf();
      for (i = 0; i < 16; i++) t[i] = n[i];
      car25519(t);
      car25519(t);
      car25519(t);
      for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
          m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
          m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
      }
      for (i = 0; i < 16; i++) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
      }
    }

    function neq25519(a, b) {
      var c = new Uint8Array(32), d = new Uint8Array(32);
      pack25519(c, a);
      pack25519(d, b);
      return crypto_verify_32(c, 0, d, 0);
    }

    function par25519(a) {
      var d = new Uint8Array(32);
      pack25519(d, a);
      return d[0] & 1;
    }

    function unpack25519(o, n) {
      var i;
      for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
      o[15] &= 0x7fff;
    }

    function A(o, a, b) {
      var i;
      for (i = 0; i < 16; i++) o[i] = (a[i] + b[i]) | 0;
    }

    function Z(o, a, b) {
      var i;
      for (i = 0; i < 16; i++) o[i] = (a[i] - b[i]) | 0;
    }

    function M(o, a, b) {
      var i, j, t = new Float64Array(31);
      for (i = 0; i < 31; i++) t[i] = 0;
      for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
          t[i + j] += a[i] * b[j];
        }
      }
      for (i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
      }
      for (i = 0; i < 16; i++) o[i] = t[i];
      car25519(o);
      car25519(o);
    }

    function S(o, a) {
      M(o, a, a);
    }

    function inv25519(o, i) {
      var c = gf();
      var a;
      for (a = 0; a < 16; a++) c[a] = i[a];
      for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a !== 2 && a !== 4) M(c, c, i);
      }
      for (a = 0; a < 16; a++) o[a] = c[a];
    }

    function pow2523(o, i) {
      var c = gf();
      var a;
      for (a = 0; a < 16; a++) c[a] = i[a];
      for (a = 250; a >= 0; a--) {
        S(c, c);
        if (a !== 1) M(c, c, i);
      }
      for (a = 0; a < 16; a++) o[a] = c[a];
    }

    function unpack25519(o, n) {
      var i;
      for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
      o[15] &= 0x7fff;
    }

    function scalarmult(q, n, p) {
      var z = new Uint8Array(32);
      var x = new Float64Array(80), r, i;
      var a = gf(), b = gf(), c = gf(),
        d = gf(), e = gf(), f = gf();
      for (i = 0; i < 31; i++) z[i] = n[i];
      z[31] = (n[31] & 127) | 64;
      z[0] &= 248;
      unpack25519(x, p);
      for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
      }
      a[0] = d[0] = 1;
      for (i = 254; i >= 0; --i) {
        r = (z[i >>> 3] >>> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
      }
      for (i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
      }
      var x32 = x.subarray(32);
      var x16 = x.subarray(16);
      inv25519(x32, x32);
      M(x16, x16, x32);
      pack25519(q, x16);
      return 0;
    }

    function scalarmult_base(q, n) {
      return scalarmult(q, n, _9);
    }

    function wrap(sk) {
      if (sk.length != 32) {
        throw new Error('Bad key size');
      }

      var pk = new Uint8Array(32);
      scalarmult_base(pk, sk);

      return {
        secretKey: sk,
        publicKey: pk,
        shared: function (pk) {
          var product = new Uint8Array(32);
          scalarmult(product, this.secretKey, pk);
          return product;
        }
      };
    }

    return {
      importKey: function (sk) {
        return wrap(ensureUint8Array(sk));
      },
      generateKey: function () {
        var sk = new Uint8Array(32);
        cryptoAPI.getRandomValues(sk);
        sk[0] &= 0xf8
        sk[31] &= 0x7f
        sk[31] |= 0x40
        return wrap(sk);
      }
    }
  })();

  var Confidentiality = (function () {
    var gcmTagSize = 16 << 3,
      gcmNonceSize = 12,
      signatureLength = 32;

    var messageAlgorithm = { name: 'AES-GCM', tagLength: gcmTagSize },
      authenticationAlgorithm = { name: 'HMAC', hash: 'SHA-256' },
      streamAlgorithm = { name: 'AES-CTR' };

    if (typeof crypto === 'undefined') {
      // Not fully compatible, @trust/webcrypto expects a hashParameters
      // object in the hash field.
      authenticationAlgorithm.hash = { name: authenticationAlgorithm.hash };
    }

    function importMessageKey(key) {
      key = ensureArrayBuffer(key);
      return cryptoAPI.subtle.importKey('raw', key, messageAlgorithm, false, ['decrypt', 'encrypt']);
    }

    function importAuthenticationKey(key) {
      key = ensureArrayBuffer(key);
      return cryptoAPI.subtle.importKey('raw', key, authenticationAlgorithm, false, ['verify', 'sign']);
    }

    function importStreamKey(key) {
      key = ensureArrayBuffer(key);
      return cryptoAPI.subtle.importKey('raw', key, streamAlgorithm, false, ['decrypt', 'encrypt']);
    }

    var methods = {};

    methods.string = function (text) {
      if (typeof text !== 'string') {
        throw Error('Argument is not a String');
      }

      if ('TextEncoder' in globals) {
        var encoded = new TextEncoder().encode(text);
        return encoded.buffer;
      }

      var buffer = new Uint8Array(text.length);
      for (var i = 0, l = text.length; i < l; i++) {
        buffer[i] = text.charCodeAt(i);
      }
      return buffer.buffer;
    }

    methods.generateMessageKey = function () {
      return cryptoAPI.getRandomValues(new Uint8Array(16));
    }

    methods.decrypt = function (message, key) {
      return new Promise(function (resolve, reject) {
        message = ensureArrayBuffer(message);
        if (message.length < gcmNonceSize) {
          throw new Error('Message too short');
        }

        var iv = message.slice(0, gcmNonceSize),
          encrypted = message.slice(gcmNonceSize);

        importMessageKey(key).then(function (key) {
          var algorithm = Object.assign({ 'iv': iv }, messageAlgorithm);
          cryptoAPI.subtle.decrypt(algorithm, key, encrypted).then(function (decrypted) {
            resolve(decrypted);
          }).catch(function (error) {
            reject(error);
          });
        }).catch(function (error) {
          reject(error);
        });
      });
    }

    methods.encrypt = function (message, key) {
      message = ensureArrayBuffer(message);
      return new Promise(function (resolve, reject) {
        importMessageKey(key).then(function (key) {
          var algorithm = Object.assign({ 'iv': cryptoAPI.getRandomValues(new Uint8Array(gcmNonceSize)) }, messageAlgorithm);
          cryptoAPI.subtle.encrypt(algorithm, key, message).then(function (encrypted) {
            resolve(concat(algorithm.iv, new Uint8Array(encrypted)));
          }).catch(reject);
        }).catch(reject);
      });
    };

    methods.generateAuthenticationKey = function () {
      return cryptoAPI.getRandomValues(new Uint8Array(16));
    };

    methods.sign = function (message, key) {
      return new Promise(function (resolve, reject) {
        message = ensureArrayBuffer(message);
        importAuthenticationKey(key).then(function (key) {
          cryptoAPI.subtle.sign(authenticationAlgorithm, key, message).then(function (signature) {
            resolve(concat(new Uint8Array(message), new Uint8Array(signature)));
          }).catch(reject);
        }).catch(reject);
      });
    };

    methods.verify = function (message, key) {
      return new Promise(function (resolve, reject) {
        message = ensureArrayBuffer(message);
        if (message.byteLength < signatureLength) {
          throw Error('Message contains no signature');
        }

        var signature = message.slice(message.length - signatureLength);
        message = message.slice(0, message.length - signatureLength);
        importAuthenticationKey(key).then(function (key) {
          cryptoAPI.subtle.verify(authenticationAlgorithm, key, signature, message).then(resolve).catch(reject);
        }).catch(reject);
      });
    };

    methods.encrypter = function (stream, key) {
      throw new Error('Streaming is not supported by the WebCrypto API');
    };

    methods.decrypter = function (stream, key) {
      throw new Error('Streaming is not supported by the WebCrypto API');
    };

    methods.secure = function (stream) {
      throw new Error('Streaming is not supported by the WebCrypto API');
    };

    methods.exchange = function (socket) {
      return new Promise(function (resolve, reject) {
        var key = Curve25519.generateKey();

        var buf = new Uint8Array(33), out = new Uint8Array(33), i, o = 0;
        out[0] = 0x19;
        for (i = 0; i < 32; i++) {
          out[i + 1] = key.publicKey[i];
        }
        socket.send(out);

        var rcv;
        rcv = function (event) {
          var data = new Uint8Array(ensureArrayBuffer(event.data));
          buf.set(data, o);
          if (event.data instanceof ArrayBuffer) {
            o += event.data.byteLength;
          } else {
            o += event.data.length;
          }
          if (o >= 33) {
            socket.removeEventListener('message', rcv);
            if (buf[0] != 0x19) {
              reject(new Error('Unsupported curve type'));
              return;
            }

            //resolve(Curve25519.importKey(buf.slice(1)));
            resolve(key.shared(buf.slice(1)));
          }
        };
        socket.addEventListener('message', rcv);
      });
    }

    return methods;
  })();

  if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
    module.exports = Confidentiality;
  }
  else {
    if (typeof define === 'function' && define.amd) {
      define([], function () {
        return Confidentiality;
      });
    }
    else {
      window.Confidentiality = Confidentiality;
    }
  }
})();

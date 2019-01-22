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

  var Confidentiality = (function () {
    function ensureArrayBuffer(data) {
      if (data instanceof ArrayBuffer) {
        // console.log("ArrayBuffer from ArrayBuffer", data.byteLength);
        return data;
      } else if (typeof data === 'string') {
        // console.log("ArrayBuffer from base64", data.length);
        return Base64Binary.decodeArrayBuffer(data);
      } else if (ArrayBuffer.isView(data)) {
        // console.log("ArrayBuffer from view", data.buffer, data.constructor.name, new ArrayBuffer(data.buffer));
        return data.buffer;
      }
      throw new Error("Don't know how to convert " + Object.prototype.toString.call(data) + " to ArrayBuffer");
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

    var gcmTagSize = 16 << 3,
      gcmNonceSize = 12,
      signatureLength = 32;

    var messageAlgorithm = { name: 'AES-GCM', tagLength: gcmTagSize },
      authenticationAlgorithm = { name: 'HMAC', hash: 'SHA-256' };

    if (typeof crypto === 'undefined') {
      // Not fully compatible, @trust/webcrypto expects a hashParameters
      // object in the hash field.
      authenticationAlgorithm.hash = {name: authenticationAlgorithm.hash};
    }

    function importMessageKey(key) {
      key = ensureArrayBuffer(key);
      return cryptoAPI.subtle.importKey('raw', key, messageAlgorithm, false, ['decrypt', 'encrypt']);
    }

    function importAuthenticationKey(key) {
      key = ensureArrayBuffer(key);
      return cryptoAPI.subtle.importKey('raw', key, authenticationAlgorithm, false, ['verify', 'sign']);
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

    methods.generateMessageKey = function() {
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

    methods.generateAuthenticationKey = function() {
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

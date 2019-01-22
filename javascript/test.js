var lib, toBase64;

if (typeof require !== 'undefined') {
  lib = require('./confidentiality');
  toBase64 = require('btoa');
} else if (typeof window !== 'undefined') {
  lib = window.Confidentiality;
  toBase64 = window.btoa;
}

// Clear logger element if it exists
(function () {
  if (typeof document === 'undefined') return;
  var element = document.getElementById('log');
  if (element) {
    element.innerText = '';
  }
})();

function logger() {
  var args = Array.prototype.slice.call(arguments).map(function (item) {
    if (typeof item === 'string') {
      return item;
    } else if (item instanceof Uint8Array) {
      if (typeof toBase64 === 'function') {
        return toBase64(String.fromCharCode.apply(null, item));
      }
      return String.fromCharCode.apply(null, item);
    }
    return item.toString();
  });

  if (typeof navigator !== 'undefined' && navigator.language) {
    var options = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hour12: false, minute: '2-digit', second: '2-digit' };
    args.unshift(new Date().toLocaleDateString(navigator.language, options));
  } else {
    args.unshift(new Date().toString());
  }

  if (typeof document !== 'undefined') {
    var element = document.getElementById('log');
    if (element) {
      element.innerText = args.join(' ') + '\n' + element.innerText;
      return;
    }
  }

  if (typeof console !== 'undefined') {
    console.log(args.join(' '));
  }
}

function testMessage() {
  var key = lib.generateMessageKey();

  logger("encrypting string with key:", key);
  lib.encrypt(lib.string("Hello, Gophers!!"), key).then(function (encrypted) {
    logger("encrypting resulted in:", encrypted.constructor.name, encrypted);

    logger("decrypting string with key:", key);
    lib.decrypt(encrypted, key).then(function (decrypted) {
      logger("decrypting resulted in:", new TextDecoder().decode(decrypted));
    }).catch(function (error) {
      logger("decrypting failed with", error);
    });
  }).catch(function (error) {
    logger("encrypting failed with", error);
  });
}

function testAuthentication() {
  var key = lib.generateAuthenticationKey();

  logger("signing string with key:", key);
  lib.sign(lib.string("Hello, Gophers!!"), key).then(function (signed) {
    logger("signing resulted in:", signed.constructor.name, signed);

    logger("verifying string with key:", key);
    lib.verify(signed, key).then(function () {
      logger("verifying ok");
    }).catch(function (error) {
      logger("verifying failed:", error);
    })
  }).catch(function (error) {
    logger("signing failed with", error);
    throw error;
  });
}

function testExchange() {
  var out = new Uint8Array(33), outOffset = 0,
    buf = new Uint8Array(33), bufOffset = 0,
    socket = {
      send: function (data) {
        out.set(data, outOffset);
        outOffset += data.length;
      },

      addEventListener: function(eventType, fn) {
        if (eventType === 'message') {
          fn({ data: 'GUgM4W7ghzsC9r72MMH4WEUhVi1xcBt/ucmhYToOqsJX'});
        }
      },
      removeEventListener: function() {}
    };

  logger("exchange");
  lib.exchange(socket).then(function(shared) {
    logger('exchange shared key:', shared.constructor.name, shared);
  });
}

testMessage();
testAuthentication();
testExchange();
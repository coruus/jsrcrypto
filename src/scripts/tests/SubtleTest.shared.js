//*******************************************************************************
//
//    Copyright 2014 Microsoft
//    
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//    
//        http://www.apache.org/licenses/LICENSE-2.0
//    
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//*******************************************************************************

/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.15.0.js" />
/// <reference path="../dotNet/dotNetInterop.js" />

var subtle;

function addEvent(elem, type, fn) {
    if (elem.addEventListener) {

        // Standards-based browsers
        elem.addEventListener(type, fn, false);
    } else if (elem.attachEvent) {

        // support: IE <9
        elem.attachEvent("on" + type, fn);
    } else {

        // Caller must ensure support for event listeners is present
        throw new Error("addEvent() was called in a context without event listener support");
    }
}

if (document) {
    addEvent(window, "load", function () { subtle = msrCrypto ? msrCrypto.subtle : null; });
}


var shared = {

    runSlowTests: false,

    initPrng: function () {

        var entropy = [];
        for (var i = 0; i < 48; i += 1) {
            entropy[i] = Math.floor(Math.random() * 256);
        }

        // init the prng with the entropy
        msrCrypto.initPrng(entropy);

    },

    typedArraySupport: (typeof Uint8Array !== "undefined"),

    isTypedArray: function (array) {
        return (Object.prototype.toString.call(array) === "[object Uint8Array]");
    },

    textToBytes: function (text) {

        var result = this.newArray(text.length);

        for (var i = 0; i < text.length; i++) {
            result[i] = text.charCodeAt(i);
        }

        return result;
    },

    getArrayResult: function (value) {

        if (Object.prototype.toString.call(value).slice(8, -1) === "ArrayBuffer") {
            var uint8 = new Uint8Array(value);
            return (uint8.length === 1) ? [uint8[0]] : Array.apply(null, uint8);
        }

        return value;

    },

    bytesToHexString: function (bytes) {
        var result = "";

        for (var i = 0 ; i < bytes.length; i++) {

            if (i % 4 == 0 && i != 0) result += "-";

            var hexval = bytes[i].toString(16).toUpperCase();
            // add a leading zero if needed
            if (hexval.length == 1)
                result += "0";

            result += hexval;
        }

        return result;
    },

    keyTextToKeyData: function (keyType, keyText) {

        switch (keyType) {
            case "aes":
                return shared.textToBytes('{"kty": "oct", "k": "' + keyText + '", "extractable": true  }');

            case "hmac":
                return shared.textToBytes('{"kty" : "oct", "alg" : "HS256", "k" : "' + keyText + '", "extractable" : true }');

            case "rsa":
                return shared.textToBytes(keyText);

            default:
                throw new Error("invalid key type");
        }

    },

    hexToBytesArray: function (hexString) {

        hexString = hexString.replace(/[^A-Fa-f0-9]/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return shared.toSupportedArray(result);
    },

    toSupportedArray: function (dataArray) {

        //already typed array and hence supported
        if (shared.isTypedArray(dataArray)) {
            return dataArray;
        }

        //convert to typed array
        if (shared.typedArraySupport) {
            return new Uint8Array(dataArray);
        }

        //typed arrays not suppored
        return dataArray;

    },

    newArray: function (size) {

        if (shared.typedArraySupport) {
            return new Uint8Array(size);
        }
        return new Array(size);
    },

    slice: function (array, start, end) {

        if (shared.typedArraySupport) {
            return array.subarray(start, end);
        }
        return array.slice(start, end);
    },

    partitionData: function (dataArray) {

        var result = [];
        var i = 0;

        while (i < dataArray.length) {
            var randomnumber = Math.floor(Math.random() * dataArray.length + 1) + i;
            result.push(shared.slice(dataArray, i, randomnumber));
            i = randomnumber;
        }

        return result;
    },

    importKey: function (keyType, keyData, callback, errorCallback, callbackParams) {

        var keyOp = null;

        if (keyType == 'hmac') {
            keyOp = subtle.importKey("Jwk", keyData, { name: "Hmac", hash: { name: "Sha-256" } }, true, []);

        } else if (keyType == 'aes-cbc') {
            keyOp = subtle.importKey("Jwk", keyData, { name: "Aes-cbc" }, true, []);

        } else if (keyType == 'aes-gcm') {
            keyOp = subtle.importKey("Jwk", keyData, { name: "Aes-gcm" }, true, []);

        } else {
            throw new Error("invalid keyType");
        }

        keyOp.oncomplete = function (e) {
            callback(e.target.result, callbackParams);
        };

        keyOp.onerror = function (e) {
            errorCallback(e);
        };

        return;
    },

    importKeyBytes: function (keyType, keyBytes, callback, errorCallback, callbackParams) {

        //convert from bytes ==> string ==> straight Base64 ==> Base64Url
        var keyText = msrCrypto.toBase64(keyBytes, true);

        var keyData = shared.keyTextToKeyData("hmac", keyText);

        shared.importKey(keyType, keyData, callback, errorCallback, callbackParams);

        return;
    },

    flip: function (percent) {

        if (percent > 1) {
            percent = (percent / 100);
        }
        return (Math.random() > percent);
    },

    hexStringToBase64Url: function (hexString) {
        var bytes = shared.hexToBytes(hexString);
        var b64Url = msrCrypto.toBase64(bytes);
        return b64Url.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
    },

    error: function (message) {
        return function (e) {
            alert("here");
            start();
            ok(false, message);
        }
    },

    setAsyncState: function (state) {

        if (state) {
            msrCrypto.subtle.forceSync = true;
        }

        if (Math.random() >= 0.5) {
            msrCrypto.subtle.forceSync = false;
        } else {
            (msrCrypto.subtle.forceSync !== undefined) && delete msrCrypto.subtle.forceSync;
        }

    },

    base64UrlToBytes: function (base64UrlText) {

        return shared.textToBytes(msrCrypto.base64ToString(base64UrlText));
    },

    getKeyData: function (keyHandle, callback, callbackParam) {

        var keyOpExp = subtle.exportKey("Jwk", keyHandle, true, []);

        keyOpExp.oncomplete = function (e) {

            // Decode the exported key
            var keyBytes = shared.getArrayResult(e.target.result);
            var keyString = String.fromCharCode.apply(null, keyBytes);
            var keyObject = JSON.parse(keyString);

            callback(keyObject, callbackParam);
        }
    },

    hexToBytes: function (hexString) {

        hexString = hexString.replace(/\-/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return result;
    },

    toBase64: msrCrypto.toBase64,

    getRsaKeyPair: function (rsaAlg, callback) {

        var keyOp1 = msCrypto.subtle.generateKey(
            rsaAlg,
            true, []);

        keyOp1.oncomplete = function (e) {

            var publicKey = e.target.result.publicKey;
            var privateKey = e.target.result.privateKey;

            var keyHandlePrivate,
                keyHandlePublic,
                keyHandlePrivateIE,
                keyHandlePublicIE

            var keyExpOp1 = msCrypto.subtle.exportKey("Jwk", privateKey);

            keyExpOp1.oncomplete = function (e0) {

                var keyImpOp1 = subtle.importKey("Jwk", new Uint8Array(e0.target.result), rsaAlg, true, []);

                keyImpOp1.oncomplete = function (e1) {

                    keyHandlePrivate = e1.target.result;

                    var keyExpOp2 = msCrypto.subtle.exportKey("Jwk", publicKey);

                    keyExpOp2.oncomplete = function (e3) {

                        var keyImpOp2 = subtle.importKey("Jwk", new Uint8Array(e3.target.result), rsaAlg, true, []);

                        keyImpOp2.oncomplete = function (e2) {

                            keyHandlePublic = e2.target.result;

                            var keyData = {
                                keyHandlePublic: keyHandlePublic,
                                keyHandlePrivate: keyHandlePrivate,
                                keyHandlePrivateIE: privateKey,
                                keyHandlePublicIE: publicKey
                            };

                            callback(keyData);
                        };
                    };
                }
            }
        }
    }
}
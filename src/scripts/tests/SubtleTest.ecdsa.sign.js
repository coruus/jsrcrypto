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
/// <reference path="~/scripts/tests/SubtleTest.shared.js" />
/// <reference path="~/scripts/ecdsa.js" />
/// <reference path="testVectors/tv_ecdsa.sign.js" />

var ecdsa_sign_vector_tests = (function () {

    function vectorTest(curveName, vectorSet) {

        var test = msrCrypto.testInterface;

        var testCount = 0;

        for (var j = 0; j < vectorSet.length; j++) {
            testCount += vectorSet[j].vectors.length;
        }

        // We do three tests per vector
        expect(testCount * 3);

        for (var j = 0; j < vectorSet.length; j++) {

            var vectors = vectorSet[j].vectors;

            var hashName = vectorSet[j].hashName.toLowerCase();

            for (var i = 0; i < vectors.length; i++) {

                var tv = vectors[i];

                var curve = test.cryptoECC["createP" + curveName]();

                var ecdsa = test.ecdsa(curve);

                var key = ecdsa.createKey(shared.hexToBytes(tv.d));

                key = {
                    privateKey: {
                        d: test.cryptoMath.digitsToBytes(key.privateKey)
                    },
                    publicKey: {
                        x: test.cryptoMath.digitsToBytes(key.publicKey.x),
                        y: test.cryptoMath.digitsToBytes(key.publicKey.y)
                    }
                }

                var hashFunction = test.hashFunctions[hashName];

                var msg = hashFunction.computeHash(shared.hexToBytes(tv.data));

                var ephemeralKey = ecdsa.createKey(shared.hexToBytes(tv.k));

                var signature = ecdsa.sign(key.privateKey, msg, ephemeralKey);

                var actualR = shared.bytesToHexString(signature.slice(0, signature.length / 2));

                var actualS = shared.bytesToHexString(signature.slice(-(signature.length / 2)));

                var expectedR = shared.bytesToHexString(shared.hexToBytes(tv.r));

                var expectedS = shared.bytesToHexString(shared.hexToBytes(tv.s));

                var verified = ecdsa.verify(key.publicKey, signature, msg);

                ok(verified, hashName + " [" + i + "] signature: " + shared.bytesToHexString(signature));
                equal(actualR, expectedR, "expected r = " + actualR);
                equal(actualS, expectedS, "expected s = " + actualS);

            }
        }

    }

    return { vectorTest: vectorTest };

})();

module("ECDSA.sign");

asyncTest("GenerateKey P-256", function () {

    var algorithm = { name: "Ecdsa", namedCurve: "p-256" };

    var keyGenOp = subtle.generateKey(algorithm);

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        shared.getKeyData(keyPair.publicKey, function (publicKeyObject) {

            shared.getKeyData(keyPair.privateKey, function (priKey, pubKey) {

                start();

                equal(keyPair.publicKey.type, "public");
                equal(keyPair.publicKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.publicKey.algorithm.namedCurve.toLowerCase(), "p-256");

                equal(pubKey.kty.toLowerCase(), "ec");
                equal(pubKey.crv.toLowerCase(), "p-256");
                equal(shared.base64UrlToBytes(pubKey.x).length, 32);
                equal(shared.base64UrlToBytes(pubKey.y).length, 32);

                equal(keyPair.privateKey.type, "private");
                equal(keyPair.privateKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.privateKey.algorithm.namedCurve.toLowerCase(), "p-256");

                equal(priKey.kty.toLowerCase(), "ec");
                equal(priKey.crv.toLowerCase(), "p-256");
                equal(shared.base64UrlToBytes(priKey.d).length, 32);
                equal(shared.base64UrlToBytes(priKey.x).length, 32);
                equal(shared.base64UrlToBytes(priKey.y).length, 32);

            }, publicKeyObject);

        });

    }

    keyGenOp.onerror = shared.error("Generate key error");

});

asyncTest("GenerateKey P-384", function () {

    var algorithm = { name: "Ecdsa", namedCurve: "p-384" };

    var keyGenOp = subtle.generateKey(algorithm);

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        shared.getKeyData(keyPair.publicKey, function (publicKeyObject) {

            shared.getKeyData(keyPair.privateKey, function (priKey, pubKey) {

                start();

                equal(keyPair.publicKey.type, "public");
                equal(keyPair.publicKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.publicKey.algorithm.namedCurve.toLowerCase(), "p-384");

                equal(pubKey.kty.toLowerCase(), "ec");
                equal(pubKey.crv.toLowerCase(), "p-384");
                equal(shared.base64UrlToBytes(pubKey.x).length, 48);
                equal(shared.base64UrlToBytes(pubKey.y).length, 48);

                equal(keyPair.privateKey.type, "private");
                equal(keyPair.privateKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.privateKey.algorithm.namedCurve.toLowerCase(), "p-384");

                equal(priKey.kty.toLowerCase(), "ec");
                equal(priKey.crv.toLowerCase(), "p-384");
                equal(shared.base64UrlToBytes(priKey.d).length, 48);
                equal(shared.base64UrlToBytes(priKey.x).length, 48);
                equal(shared.base64UrlToBytes(priKey.y).length, 48);

            }, publicKeyObject);

        });

    }

    keyGenOp.onerror = shared.error("Generate key error");

});

asyncTest("Sign & Verify P-256 SHA-256", function () {



    var keyGenOp = subtle.generateKey({ name: "Ecdsa", namedCurve: "p-256" });

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        var data = [];

        for (var j = 0; j < Math.random() * 300; j++) {
            data.push(Math.random() * 256);
        }

        var algorithm = { name: "Ecdsa", namedCurve: "p-256", hash: { name: "Sha-256" } };

        var cryptoOp = subtle.sign(algorithm, keyPair.privateKey, data);

        cryptoOp.oncomplete = function (e) {

            var signatureBytes = shared.getArrayResult(e.target.result);

            var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data);

            opVerify.oncomplete = function (e) {

                var result = e.target.result;

                start();

                ok(result, "s = " + shared.bytesToHexString(signatureBytes));
            }

            opVerify.onerror = shared.error("Verify error");

        }

        cryptoOp.onerror = shared.error("Sign error");

    }

    keyGenOp.onerror = shared.error("Generate key error");



});

asyncTest("Sign & Verify P-384 SHA-256", function () {

    var keyGenOp = subtle.generateKey({ name: "Ecdsa", namedCurve: "p-384" });

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        var data = [];

        for (var j = 0; j < Math.random() * 300; j++) {
            data.push(Math.random() * 256);
        }

        var algorithm = { name: "Ecdsa", namedCurve: "p-384", hash: { name: "Sha-256" } };

        var cryptoOp = subtle.sign(algorithm, keyPair.privateKey, data);

        cryptoOp.oncomplete = function (e) {

            var signatureBytes = shared.getArrayResult(e.target.result);

            var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data);

            opVerify.oncomplete = function (e) {

                var result = e.target.result;

                start();

                ok(result, "s = " + shared.bytesToHexString(signatureBytes));
            }

            opVerify.onerror = shared.error("Verify error");

        }

        cryptoOp.onerror = shared.error("Sign error");
    }

    keyGenOp.onerror = shared.error("Generate key error");

});

// These tests use the internal APIs, so they won't be available without using
// msrCrypto.test.js
if (cryptoLibraries["msrcrypto.test.js"]) {

    _msrCrypto = msrCrypto;

    msrCrypto = cryptoLibraries["msrcrypto.test.js"];

    test("Test Vectors P-256", function () {

        _msrCrypto = msrCrypto;

        msrCrypto = cryptoLibraries["msrcrypto.test.js"];

        ecdsa_sign_vector_tests.vectorTest("256", tv_ecdsa_sign["P-256"]);

        msrCrypto = _msrCrypto;

    });

    test("Test Vectors P-384", function () {

        _msrCrypto = msrCrypto;

        msrCrypto = cryptoLibraries["msrcrypto.test.js"];

        ecdsa_sign_vector_tests.vectorTest("384", tv_ecdsa_sign["P-384"]);

        msrCrypto = _msrCrypto;

    });
    
}

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
/// <reference path="testVectors/tv_rsa.sign.pss.js" />

var rsa_sign_pss_vector_tests = (function () {

    var vectorCount = 0;

    var results = [];

    function importRsaKey(keyJsonText, algorithmName, callback, errorCallback) {

        var keyData = shared.textToBytes(keyJsonText);

        var keyOp = subtle.importKey("Jwk", keyData, { name: algorithmName }, true, []);

        keyOp.oncomplete = function (e) {
            callback(e.target.result);
        };

        keyOp.onerror = function (e) {
            errorCallback(e);
        };
    }

    function signComplete(hashName, expectedHex, resultArray) {

        return function (e) {

            var signatureHex = shared.bytesToHexString(shared.getArrayResult(e.target.result));
            resultArray.push({ hash: hashName, signature: signatureHex, expected: expectedHex });

            if (resultArray.length === vectorCount) {
                start();
                for (var i = 0; i < resultArray.length; i++) {
                    equal(
                        resultArray[i].signature,
                        resultArray[i].expected,
                        resultArray[i].hash + " " + resultArray[i].expected);
                }
            }

        };
    };

    function vectorTest(key, vectors, sync) {

        expect(vectors.length);

        results = [];

        vectorCount = vectors.length;

        var keyBase = { "kty": "RSA", "extractable": true };
        keyBase.n = shared.hexStringToBase64Url(key.n);
        keyBase.e = shared.hexStringToBase64Url(key.e);
        keyBase.d = shared.hexStringToBase64Url(key.d);

        var keyString = JSON.stringify(keyBase);

        importRsaKey(keyString, "rsa-pss", function (keyHandle) {

            for (var i = 0; i < vectors.length; i++) {

                var hash = vectors[i].hashName;
                var dataBytes = shared.hexToBytesArray(vectors[i].data);
                var saltBytes = shared.hexToBytesArray(vectors[i].salt);
                var expectedHex =
                    shared.bytesToHexString(
                        shared.hexToBytesArray(vectors[i].signature)
                        );

                var cryptoOp = subtle.sign(
                    {
                        name: "rSa-pss",
                        hash: { name: hash },
                        salt: saltBytes
                    },
                    keyHandle,
                    dataBytes);

                cryptoOp.oncomplete = signComplete(
                    hash,
                    expectedHex,
                    results);

                cryptoOp.onerror = shared.error("sign error");

            }

        }, shared.error("key import error"));
    }

    return {
        vectorTest: vectorTest
    };

})();

module("RSA.sign.pss");

asyncTest("vectors mod 1024", function () {

    rsa_sign_pss_vector_tests.vectorTest(
        tv_rsa_sign_pss.keys["1024"],
        tv_rsa_sign_pss.vectors["1024"],
        false);

});

asyncTest("vectors mod 2048", function () {

    rsa_sign_pss_vector_tests.vectorTest(
        tv_rsa_sign_pss.keys["2048"],
        tv_rsa_sign_pss.vectors["2048"],
        false);

});

if (shared.runSlowTests) {

    asyncTest("vectors mod 3072", function () {

        rsa_sign_pss_vector_tests.vectorTest(
            tv_rsa_sign_pss.keys["3072"],
            tv_rsa_sign_pss.vectors["3072"],
            false);

    });

}






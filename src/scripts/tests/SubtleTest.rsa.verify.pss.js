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
/// <reference path="testVectors/tv_rsa.verify.pss.js" />

var rsa_verify_pss_vector_tests = (function () {

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

    function importKeyComplete(hashName, message, signature, expected, iteration) {

        return function (keyHandle) {

            var cryptoOp = subtle.verify(
                {
                    name: "rSassa-pkcs1-v1_5",
                    hash: { name: hashName }
                },
                keyHandle,
                signature,
                message);

            cryptoOp.oncomplete = verifyComplete(
                hashName,
                signature,
                expected,
                results,
                iteration);

            cryptoOp.onerror = shared.error("verify error");
        };
    }

    function verifyComplete(hashName, signature, expectedResult, resultArray, iteration) {

        return function (e) {

            var actualResult = e.target.result;

            resultArray.push({ hash: hashName, actual: actualResult, signature: signature, expected: expectedResult, iteration: iteration });

            if (resultArray.length === vectorCount) {
                checkResults(resultArray);
            }

        };
    };

    function checkResults(resultArray) {
        start();
        for (var i = 0; i < resultArray.length; i++) {
            var p = resultArray[i];
            equal(
                p.actual,
                p.expected,
                p.hash + " [" + p.iteration + "] " +
                p.actual + "/" + p.expected + " \t" +
                shared.bytesToHexString(p.signature).substring(0, 17) + "...");
        }
    }

    function vectorTest(vectorSet, sync) {

        vectorCount = 0;

        results = [];

        // get test count
        for (var k = 0; k < vectorSet.length; k++) {
            vectorCount += vectorSet[k].vectors.length;
        }

        for (var k = 0; k < vectorSet.length; k++) {

            var keySet = vectorSet[k];

            var testVectors = keySet.vectors;

            var keyBase = { "kty": "RSA", "extractable": true };
            keyBase.n = shared.hexStringToBase64Url(keySet.n);

            for (var i = 0; i < testVectors.length; i++) {

                var vector = testVectors[i];

                keyBase.e = shared.hexStringToBase64Url(vector.e);
                keyBase.d = shared.hexStringToBase64Url(vector.d);

                var keyString = JSON.stringify(keyBase);

                importRsaKey(keyString, "rsassa-pkcs1-v1_5",
                    importKeyComplete(
                                    vector.hashName,
                                    shared.hexToBytesArray(vector.data),
                                    shared.hexToBytesArray(vector.signature),
                                    vector.result,
                                    i),
                    shared.error("key import error"));

            }
        }
    };

    return {
        vectorTest: vectorTest
    };

})();

module("RSA.verify.pss");

// tv_rsa_verify_pss is defined in the vector file

asyncTest("vectors mod 1024", function () {

    rsa_verify_pss_vector_tests.vectorTest(
        tv_rsa_verify_pss["1024"],
        false);

});

asyncTest("vectors mod 1536", function () {

    rsa_verify_pss_vector_tests.vectorTest(
        tv_rsa_verify_pss["1536"],
        false);

});

asyncTest("vectors mod 2048", function () {

    rsa_verify_pss_vector_tests.vectorTest(
        tv_rsa_verify_pss["2048"],
        false);

});

if (shared.runSlowTests) {

    asyncTest("vectors mod 3072", function () {

        rsa_verify_pss_vector_tests.vectorTest(
            tv_rsa_verify_pss["3072"],
            false);

    });

    asyncTest("vectors mod 4096", function () {
    
        rsa_verify_pss_vector_tests.vectorTest(
            tv_rsa_verify_pss["4096"],
            false);
    
    });

}






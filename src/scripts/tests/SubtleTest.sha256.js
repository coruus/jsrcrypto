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
/// <reference path="testVectors/tv_sha224_short.js" />
/// <reference path="testVectors/tv_sha224_long.js" />
/// <reference path="testVectors/tv_sha256_short.js" />
/// <reference path="testVectors/tv_sha256_long.js" />

var hash256Results = [];

function hash256Complete(expectedHex, resultArray, expectedResultCount) {

    return function (e) {

        var hashHex = shared.bytesToHexString(shared.getArrayResult(e.target.result));
        resultArray.push({ hash: hashHex, expected: expectedHex });

        if (resultArray.length === expectedResultCount) {
            start();
            for (var i = 0; i < resultArray.length; i++) {
                equal(resultArray[i].hash, resultArray[i].expected, "should be " + resultArray[i].expected);
            }
        }

    };
};

function aesVectorTest(vectorArray, resultsArray, shaAlgName, sync, process) {

    expect(vectorArray.length);
    resultsArray = [];

    shared.setAsyncState(!sync);

    for (var i = 0; i < vectorArray.length; i++) {

        var dataBytes = shared.toSupportedArray(vectorArray[i].data);
        var expectedHex = shared.bytesToHexString(vectorArray[i].hash);
        var cryptoOp;

        if (process) {
            cryptoOp = subtle.digest({ name: shaAlgName });
        } else {
            cryptoOp = subtle.digest({ name: shaAlgName }, dataBytes);
        }

        cryptoOp.oncomplete = hash256Complete(expectedHex, resultsArray, vectorArray.length);
        cryptoOp.onerror = function (e) { ok(false, "Error: " + e.message); };

        if (process) {
            var sections = shared.partitionData(dataBytes);
            for (var j = 0; j < sections.length; j++) {
                cryptoOp.process(sections[j]);
            }
            cryptoOp.finish();
        }
    }
};

// #region SHA-224

module("SHA-224");

asyncTest("SHA-224 vectors short", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", false, false);

});

asyncTest("SHA-224 vectors short process sync", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", true, true);

});

asyncTest("SHA-224 vectors short process async", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", false, true);

});

asyncTest("SHA-224 vectors long", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", false, false);

});

asyncTest("SHA-224 vectors long process sync", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", true, true);

});

asyncTest("SHA-224 vectors long process async", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", false, true);

});

// #endregion SHA-224

// #region SHA-256

module("SHA-256");

asyncTest("SHA-256 vectors short", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", false, false);

});

asyncTest("SHA-256 vectors short process sync", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", true, true);

});

asyncTest("SHA-256 vectors short process async", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", false, true);

});

asyncTest("SHA-256 vectors long", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", false, false);

});

asyncTest("SHA-256 vectors long process sync", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", true, true);

});

asyncTest("SHA-256 vectors long process async", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", false, true);

});

// #endregion SHA-256




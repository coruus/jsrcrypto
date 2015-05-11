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

// #region WrapKey

module("Wrap Key");

/// Wrap an AES-CBC key with a RSA-OAEP key using msrCrypto
/// then unwrap the key using IE11 msCrypto

if (typeof msCrypto !== "undefined") {  // msCrypto is only defined in IE

    var ieCrypto = msCrypto;

    asyncTest("JS to IE OAEP/AES-GCM", function () {

        // Generate encryptionKey:
        var importOp = msrCrypto.subtle.generateKey(
        { name: "Aes-CBC", length: 128 },
        true, ["sign", "verify"]);

        var encryptedData,
            encryptedData1;

        importOp.oncomplete = function (e) {

            var encryptionKey = e.target.result;

            var cryptoOp = msrCrypto.subtle.encrypt(
                {
                    name: "Aes-CBC",
                    iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                }, encryptionKey, [1, 2, 3]);

            cryptoOp.oncomplete = function (e) {

                encryptedData = shared.getArrayResult(e.target.result);

                shared.getRsaKeyPair(
                    { name: "rSa-OAEP", modulusLength: 1024 },
                    function (keyPair) {

                        var publicKey = keyPair.keyHandlePublic;
                        var privateKey = keyPair.keyHandlePrivateIE;

                        var wrapOp = msrCrypto.subtle.wrapKey(
                            encryptionKey,
                            publicKey,
                            { name: "Aes-GCM" });

                        wrapOp.oncomplete = function (e) {

                            var wrappedKeyData = e.target.result;

                            var unWrapOp = ieCrypto.subtle.unwrapKey(
                                new Uint8Array(wrappedKeyData),
                                { name: "Aes-CBC" },
                                privateKey, true, ["encrypt", "decrypt"]);

                            unWrapOp.onerror = shared.error("unwrapKey");

                            unWrapOp.oncomplete = function (e) {

                                var unwrappedEncryptionKey = e.target.result;

                                var cryptoOp1 = ieCrypto.subtle.encrypt(
                                    {
                                        name: "Aes-CBC",
                                        iv: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                                    }, unwrappedEncryptionKey, new Uint8Array([1, 2, 3]));

                                cryptoOp1.oncomplete = function (e) {

                                    start();

                                    encryptedData1 = shared.getArrayResult(e.target.result);

                                    equal(encryptedData.join(), encryptedData1.join(), encryptedData.join() + "==" + encryptedData1.join());
                                };
                            };
                        };

                        wrapOp.onerror = shared.error("wrapKey");

                    });
            };
        };
    });

    asyncTest("IE to JS OAEP/AES-GCM", function () {

        // Generate encryptionKey:
        var importOp = ieCrypto.subtle.generateKey(
        { name: "Aes-CBC", length: 128 },
        true, ["sign", "verify"]);

        importOp.oncomplete = function (e) {

            var encryptionKey = e.target.result;

            shared.getRsaKeyPair({ name: "rSa-OAEP", modulusLength: 1024 }, function (keyPair) {

                var publicKey = keyPair.keyHandlePublicIE;
                var privateKey = keyPair.keyHandlePrivate;

                var wrapOp = ieCrypto.subtle.wrapKey(
                    encryptionKey,
                    publicKey,
                    { name: "Aes-GCM" });

                wrapOp.oncomplete = function (e) {

                    var wrappedKeyData = e.target.result;

                    var unWrapOp = msrCrypto.subtle.unwrapKey(
                        new Uint8Array(wrappedKeyData),
                        { name: "Aes-CBC" },
                        privateKey, true, ["encrypt", "decrypt"]);

                    unWrapOp.onerror = shared.error("unwrapKey");

                    unWrapOp.oncomplete = function (e) {
                        start();
                        var unwrappedEncryptionKey = e.target.result;
                        ok(true);
                    };

                };

                wrapOp.onerror = shared.error("wrapKey");

            });

        };
    });

    asyncTest("JS to JS OAEP/AES-GCM", function () {

        // Generate encryptionKey:
        var importOp = msrCrypto.subtle.generateKey(
        { name: "Aes-CBC", length: 128 },
        true, ["sign", "verify"]);

        importOp.oncomplete = function (e) {

            var encryptionKey = e.target.result;

            shared.getRsaKeyPair({ name: "rSa-OAEP", modulusLength: 1024 }, function (keyPair) {

                var publicKey = keyPair.keyHandlePublic;
                var privateKey = keyPair.keyHandlePrivate;

                var wrapOp = msrCrypto.subtle.wrapKey(
                    encryptionKey,
                    publicKey,
                    { name: "Aes-GCM" });

                wrapOp.oncomplete = function (e) {

                    var wrappedKeyData = e.target.result;

                    var unWrapOp = msrCrypto.subtle.unwrapKey(
                        new Uint8Array(wrappedKeyData),
                        { name: "Aes-CBC" },
                        privateKey, true, ["encrypt", "decrypt"]);

                    unWrapOp.onerror = shared.error("unwrapKey");

                    unWrapOp.oncomplete = function (e) {
                        start();
                        var unwrappedEncryptionKey = e.target.result;
                        ok(true);
                    };

                };

                wrapOp.onerror = shared.error("wrapKey");

            });

        };
    });

}
// #endregion WrapKey
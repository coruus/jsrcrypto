﻿//*******************************************************************************
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

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoUtilities */
/* global rsaShared */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="random.js " />
/// <reference path="rsa-base.js " />

/// <dictionary>Struct,unpad,Hashp,maskeddb,rsa,utils</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var rsaMode = rsaMode || {};
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>

rsaMode.oaep = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        random = msrcryptoPseudoRandom,
        size = keyStruct.n.length;

    if (hashFunction === null) {
        throw new Error("must supply hashFunction");
    }

    function pad(/*@type(Array)*/ message, /*@optional*/ label) {

        var lHash, psLen, psArray, i, db, seed;
        var dbMask, maskeddb, seedMask, maskedSeed;
        var /*@type(Array)*/ encodedMessage;

        if (message.length > (size - 2 * (hashFunction.hashLen / 8) - 2)) {
            throw new Error("Message too long.");
        }

        label || (label = []);

        lHash = hashFunction.computeHash(/*@static_cast(Digits)*/label);

        psLen = size - message.length - (2 * lHash.length) - 2;
        psArray = utils.getVector(psLen);

        // 'db' = 'lHash' || 'psArray' || 0x01 || message
        db = lHash.concat(psArray, [1], message);

        seed = random.getBytes(lHash.length);

        dbMask = rsaShared.mgf1(seed, size - lHash.length - 1, hashFunction);

        maskeddb = utils.xorVectors(db, dbMask);

        seedMask = rsaShared.mgf1(maskeddb, lHash.length, hashFunction);

        maskedSeed = utils.xorVectors(seed, seedMask);

        encodedMessage = [0].concat(maskedSeed).concat(maskeddb);

        message = encodedMessage.slice();

        return encodedMessage;
    }

    function unpad(/*@type(Array)*/ encodedBytes, /*@optional*/ labelBytes) {

        var lHash, maskedSeed, maskeddb, seedMask;
        var seed, dbMask, db;
        var lHashp;

        if (!labelBytes) {
            labelBytes = [];
        }

        lHash = hashFunction.computeHash(labelBytes);

        if (encodedBytes[0] !== 0) {
            throw new Error("Encryption Error");
        }

        maskedSeed = encodedBytes.slice(1, lHash.length + 1);
        maskeddb = encodedBytes.slice(lHash.length + 1);

        seedMask = rsaShared.mgf1(maskeddb, lHash.length, hashFunction);
        seed = utils.xorVectors(maskedSeed, seedMask);
        dbMask = rsaShared.mgf1(seed, size - lHash.length - 1, hashFunction);

        db = utils.xorVectors(maskeddb, dbMask);

        lHashp = db.slice(0, lHash.length);

        // lHashp should equal lHash or 'Encryption Error'
        if (!utils.arraysEqual(lHash, lHashp)) {
            throw new Error("Encryption Error");
        }

        db = db.slice(lHash.length);

        // There will be a bunch of zeros followed by a 
        var i = db.indexOf(1);

        return db.slice(i + 1);
    }

    return {

        pad: function (/*@type(Array)*/ messageBytes, /*@optional*/ labelBytes) {
            return pad(messageBytes, labelBytes);
        },

        unpad: function (/*@type(Array)*/ encodedBytes, /*@optional*/ labelBytes) {
            return unpad(encodedBytes, labelBytes);
        }
    };

};

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

/// #region JSCop/JsHint

/* global msrcryptoUtilities */

/// <reference path="utilities.js" />

/// <dictionary>alg,Jwk,msrcrypto,utils</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoJwk = (function () {

    var utils = msrcryptoUtilities;

    function stringToArray(stringData) {

        var result = [];

        for (var i = 0; i < stringData.length; i++) {
            result[i] = stringData.charCodeAt(i);
        }

        if (result[result.length - 1] === 0) {
            result.pop();
        }

        return result;
    }

    function getKeyType(keyHandle) {

        var algType = keyHandle.algorithm.name.slice(0, 3).toLowerCase();

        if (algType === "rsa") {
            return "RSA";
        }

        if (algType === "ecd") {
            return "EC";
        }

        return "oct";
    }

    function keyToJwk(keyHandle, keyData) {

        var key = {};

        key.kty = getKeyType(keyHandle);
        key.extractable = keyHandle.extractable;
        
        // Using .pop to determine if a property value is an array.
        if (keyData.pop) {
            key.k = utils.toBase64(keyData, true);
        } else {
            // Convert the base64Url properties to byte arrays
            for (var property in keyData) {
                if (keyData[property].pop) {
                    key[property] = utils.toBase64(keyData[property], true);
                }
            }
        }

        if (keyHandle.algorithm.namedCurve) {
            key["crv"] = keyHandle.algorithm.namedCurve;
        }

        var stringData = JSON.stringify(key, null, '\t');

        return stringToArray(stringData);

    }

    // 'jwkKeyData' is an array of bytes. Each byte is a charCode for a json key string
    function jwkToKey(keyData, algorithm, propsToArray) {

        // Convert array of string data to a json string
        var jsonString = String.fromCharCode.apply(null, keyData);

        // Convert the json string to an object
        var jsonKeyObject = JSON.parse(jsonString);

        // Convert the base64url encoded properties to byte arrays
        for (var i = 0; i < propsToArray.length; i += 1) {
            var propValue = jsonKeyObject[propsToArray[i]];
            if (propValue) {
                jsonKeyObject[propsToArray[i]] =
                    utils.base64ToBytes(propValue);
            }
        }

        return jsonKeyObject;
    }

    return {
        keyToJwk: keyToJwk,
        jwkToKey: jwkToKey
    };
})();
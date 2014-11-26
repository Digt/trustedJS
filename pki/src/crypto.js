trusted.CryptoStatus = {
    Done: 0,
    Pending: 1,
    Error: 2
};

function Crypto() {
    var crypto = null;
    var type = null;

    this.__proto__ = {
        // type can be 'webcrypto', 'nodejs'
        get type() {
            return type;
        },
        get crypto() {
            return crypto;
        }
    };

    function init() {
        if (typeof require !== "undefined") {
            crypto = require("crypto");
            type = "nodejs";
            //console.log(require("crypto").getHashes());
        }
        else {
            if ("crypto" in window) {
                crypto = window.crypto.subtle;
                type = "webcrypto";
            }
            else if ("msCrypto" in window) {
                crypto = window.msCrypto.subtle;
                type = "webcrypto";
            } else
                throw "Crypto: Your browser doesn't have crypto module."
        }
    }

    this.createHash = function(name) {
        return new Hash(name);
    };
    this.createVerify = function(name) {
        return new Verify(name);
    };
    this.createSign = function(name) {
        return new Sign(name);
    };

    this.createCipher = function() {
        switch (arguments.length) {
            case 2:
                return new Cipher(arguments[0], arguments[1]);
                break
            case 3:
                return new Cipher(arguments[0], arguments[1], arguments[2]);
                break
            default:
                throw "Crypto.createCipher: Has wrong number of parameters";
        }
    };
    this.createDecipher = function() {
        switch (arguments.length) {
            case 2:
                return new Decipher(arguments[0], arguments[1]);
                break
            case 3:
                return new Decipher(arguments[0], arguments[1], arguments[2]);
                break
            default:
                throw "Crypto.createDecipher: Has wrong number of parameters";
        }
    };
    this.pbkdf2 = function(password, salt, iterations, keylen) {
        switch (trusted.Crypto.type) {
            case "webcrypto":
                throw "Method 'pkdf2' is not supported in WebCrypto"
                break;
            case "nodejs":
                return crypto.pkdf2(password, salt, iterations, keylen);
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    };


    init.call(this, arguments);
    console.warn("Application run with '%s' crypto module", type);
}

function Hash() {
    var cache;

    this.update = function(data) {
        var err_t = "Hash.update: ";
        if (data === undefined)
            throw err_t + "Parameter 'data' is undefined"
        if (!trusted.isString(data))
            throw err_t + "Parameter 'data' must be type of String"
        switch (trusted.Crypto.type) {
            case "webcrypto":
                if (cache.data === undefined)
                    cache.data = "";
                cache.data += data;
                break;
            case "nodejs":
                cache.hash.update(data);
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    };

    this.digest = function() {
        var err_t = "Hash.digest: ";
        return new Promise(function(resolve, reject) {
            switch (trusted.Crypto.type) {
                case "webcrypto":
                    var data = Der.toUint8Array(cache.data);
                    var algorithm = cache.algorithm;
                    if (algorithm.hash !== undefined)
                        algorithm = algorithm.hash;
                    trusted.Crypto.crypto.digest(algorithm, data).then(
                            function(v) {
                                resolve(String.fromCharCode.apply(null, new Uint8Array(v))); // to DER string
                            },
                            function(e) {
                                reject(e.message);
                            }
                    );
                    break;
                case "nodejs":
                    resolve(cache.hash.digest("binary"));
                    break;
                default:
                    reject(err_t + "Unknown crypto module");
            }
        });
    };

    function init(algorithm) {
        var err_t = "Crypto.createHash: ";
        if (!trusted.isObject(algorithm))
            try {
                algorithm = new trusted.PKI.Algorithm.fromName(algorithm);
            } catch (e) {
                throw err_t + "Error on creating algorithm. " + e;
            }
        if (algorithm.type !== "Algorithm")
            throw err_t + "Parameter 'algorithm' must be type of Algorithm"

        cache = {};

        switch (trusted.Crypto.type) {
            case "webcrypto":
                cache.algorithm = algorithm.toCrypto();
                break;
            case "nodejs":
                cache.hash = require("crypto").createHash(algorithm.toCrypto());
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    }

    init.call(this, arguments[0]);
}

function Verify() {
    var cache;

    this.update = function(data) {
        var err_t = "Hash.update: ";
        if (data === undefined)
            throw err_t + "Parameter 'data' is undefined"
        if (!trusted.isString(data))
            throw err_t + "Parameter 'data' must be type of String"
        switch (trusted.Crypto.type) {
            case "webcrypto":
                if (cache.data === undefined)
                    cache.data = "";
                cache.data += data;
                break;
            case "nodejs":
                cache.verifier.update(data);
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    };

    /**
     * Проверка подписи
     * @param {type} object PublicKey, Certificate
     * @param {type} signature DER String of signature
     * @returns {Promise}
     */
    this.verify = function(object, signature) {
        var err_t = "Verify: ";
        return new Promise(function(resolve, reject) {
            var key;
            switch (object.type) {
                case "Certificate":
                    key = object.publicKey;
                    break;
                case "PublicKey":
                    key = object;
                    break
                default:
                    reject(err_t + "Unknown type of paramenter 'object'");
            }

            switch (trusted.Crypto.type) {
                case "webcrypto":
                    // (1) import key
                    key = Der.toUint8Array(key.encode());
                    trusted.Crypto.crypto.importKey("spki", key, cache.algorithm, false, ["verify"]).then(
                            function(v) {
                                key = v;
                                //console.log(key);
                                //console.log("Signed data:",Der.toHex(cache.data));
                                //console.log("Signature:",Der.toHex(signature));
                                //console.log("Signed Data:",Der.toHex(cache.data));
                                return trusted.Crypto.crypto.verify(key.algorithm, key, Der.toUint8Array(signature), Der.toUint8Array(cache.data));
                            }
                    ).then(function(v) {
                        resolve(v);
                    }
                    ).catch(function(e) {
                        reject(e);
                    });
                    break;
                case "nodejs":
                    key = key.export(trusted.ExportType.pem);
                    resolve(cache.verifier.verify(key, signature));
                    break;
                default:
                    reject(err_t + "Unknown crypto module");
            }
        });
    };

    function init(algorithm) {
        var err_t = "Crypto.createVerify: ";
        if (!trusted.isObject(algorithm))
            try {
                algorithm = new trusted.PKI.Algorithm.fromName(algorithm);
            } catch (e) {
                throw err_t + "Error on creating algorithm. " + e;
            }
        if (algorithm.type !== "Algorithm")
            throw err_t + "Parameter 'algorithm' must be type of Algorithm"

        cache = {};

        switch (trusted.Crypto.type) {
            case "webcrypto":
                cache.algorithm = algorithm.toCrypto();
                break;
            case "nodejs":
                console.log("-----Digest algorithm-----");
                console.log(algorithm);
                console.log(algorithm.toCrypto());
                cache.verifier = require("crypto").createVerify(algorithm.toCrypto());
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    }

    init.call(this, arguments[0]);
}

function Sign() {
    var cache;

    this.update = function(data) {
        var err_t = "Sign.update: ";
        if (data === undefined)
            throw err_t + "Parameter 'data' is undefined"
        if (!trusted.isString(data))
            throw err_t + "Parameter 'data' must be type of String"
        switch (trusted.Crypto.type) {
            case "webcrypto":
                if (cache.data === undefined)
                    cache.data = "";
                cache.data += data;
                break;
            case "nodejs":
                cache.signer.update(data);
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    };

    this.sign = function(privateKey) {
        var err_t = "Sign.sign: ";
        return new Promise(function(resolve, reject) {
            if (privateKey.type !== "PrivateKey")
                reject(err_t + "Parameter 'privateKey' must be type of PrivateKey");
            switch (trusted.Crypto.type) {
                case "webcrypto":
                    // (1) put PEM of private key to PKCS8
                    var key = Der.toUint8Array(privateKey.toPKCS8());
                    console.log("Signer.sign(Attribute):",privateKey.algorithm.toCrypto());
                    // (2) import key
                    trusted.Crypto.crypto.importKey("pkcs8", key, privateKey.algorithm.toCrypto(), false, ["sign"]).then(
                            function(v) {
                                key = v;
                                console.log(key);
                                //console.log("Signed data:",Der.toHex(cache.data));
                                //console.log("Signature:",Der.toHex(signature));
                                //return trusted.Crypto.crypto.verify(key.algorithm, key, Der.toUint8Array(signature), Der.toUint8Array(cache.data));
                                return Promise.resolve("true");
                            }
                    ).then(function(v) {
                        resolve(v);
                    }
                    ).catch(function(e) {
                        reject(e);
                    });
                    break;
                case "nodejs":
                    var signature = cache.signer.sign(privateKey.export(trusted.ExportType.pem), "binary");
                    resolve(signature);
                    break;
                default:
                    reject(err_t + "Unknown crypto module");
            }
        });
    };

    function init(algorithm) {
        var err_t = "Crypto.createSign: ";
        if (!trusted.isObject(algorithm))
            try {
                algorithm = new trusted.PKI.Algorithm.fromName(algorithm);
            } catch (e) {
                throw err_t + "Error on creating algorithm. " + e;
            }
        if (algorithm.type !== "Algorithm")
            throw err_t + "Parameter 'algorithm' must be type of Algorithm"

        cache = {};

        switch (trusted.Crypto.type) {
            case "webcrypto":
                cache.algorithm = algorithm;
                break;
            case "nodejs":
                cache.signer = require("crypto").createSign(algorithm.toCrypto());
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    }

    init.call(this, arguments[0]);
}

function Cipher() {
    var cache;

    this.update = function(data, encoding) {
        var err_t = "Sign.update: ";
        if (data === undefined)
            throw err_t + "Parameter 'data' is undefined"
        if (!trusted.isString(data))
            throw err_t + "Parameter 'data' must be type of String"
        switch (trusted.Crypto.type) {
            case "webcrypto":
                if (cache.data === undefined)
                    cache.data = "";
                cache.data += data;
                break;
            case "nodejs":
                if (encoding === undefined)
                    encoding = "text";
                switch (encoding) {
                    case "text":
                        data = trusted.Utf8.toDer(data);
                        break;
                    case "binary":
                        break;
                    default:
                        throw err_t + "Unknown encoding type '" + encoding + "'"
                }
                cache.data = cache.cipher.update(data, "binary", 'binary');
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    };

    this.final = function() {
        var err_t = "Cipher.final: ";
        return new Promise(function(resolve, reject) {

            switch (trusted.Crypto.type) {
                case "webcrypto":
                    break;
                case "nodejs":
                    resolve(cache.data += cache.cipher.final('binary'));
                    break;
                default:
                    reject(err_t + "Unknown crypto module");
            }
        });
    };

    function init(args) {
        var err_t = "Cipher.init: ";
        var algorithm, key, psw, iv;
        switch (args.length) {
            case 2:
                algorithm = args[0];
                psw = args[1];
                // Check psw (STRING)
                if (!trusted.isString(psw))
                    throw err_t + "Parameter 'password' must be type of String";
                break
            case 3:
                algorithm = args[0];
                key = args[1];
                iv = args[2];
                // Check key (DER STRING | PrivateKey)
                if (trusted.isObject(key)) {
                    if (key.type !== "PrivateKey")
                        throw err_t + "Parameter 'key' must be type of PrivateKey";
                    // PrivateKey to DER
                    key = key.export();
                } else if (!trusted.isString(key))
                    throw err_t + "Parameter 'key' must be type of String";
                // Check iv (DER STRING)
                if (!trusted.isString(iv))
                    throw err_t + "Parameter 'iv' must be type of String";
                break
            default:
                throw err_t + "Has wrong number of parameters";
        }
        // Check algorithm ( STRING | OBJECT::Algorithm)
        if (!trusted.isObject(algorithm))
            try {
                algorithm = new trusted.PKI.Algorithm.fromName(algorithm);
            } catch (e) {
                throw err_t + "Error on creating algorithm. " + e;
            }
        if (algorithm.type !== "Algorithm")
            throw err_t + "Parameter 'algorithm' must be type of Algorithm"

        cache = {};

        switch (trusted.Crypto.type) {
            case "webcrypto":

                break;
            case "nodejs":
                switch (args.length) {
                    case 2:
                        cache.cipher = require("crypto").createCipher(algorithm.toCrypto(), psw);
                        break;
                    case 3:
                        cache.cipher = require("crypto").createCipheriv(algorithm.toCrypto(), key, iv);
                        break;
                }
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    }

    init.call(this, arguments);
}

function Decipher() {
    var cache;

    this.update = function(data, encoding) {
        var err_t = "Decipher.update: ";
        if (data === undefined)
            throw err_t + "Parameter 'data' is undefined"
        if (!trusted.isString(data))
            throw err_t + "Parameter 'data' must be type of String"
        if (encoding === undefined)
            encoding = "text";
        switch (encoding) {
            case "text":
                encoding = "utf8";
                break;
            case "binary":
                break;
            default:
                throw err_t + "Unknown encoding type '" + encoding + "'"
        }
        switch (trusted.Crypto.type) {
            case "webcrypto":
                if (cache.data === undefined)
                    cache.data = "";
                cache.data += data;
                break;
            case "nodejs":
                cache.data = cache.decipher.update(data, 'binary', 'binary');
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    };

    this.final = function(encoding) {
        var err_t = "Decipher.final: ";
        return new Promise(function(resolve, reject) {
            if (encoding === undefined)
                encoding = "text";
            switch (encoding) {
                case "text":
                    break;
                case "binary":
                    break;
                default:
                    reject(err_t + "Unknown encoding type '" + encoding + "'");
            }
            switch (trusted.Crypto.type) {
                case "webcrypto":
                    break;
                case "nodejs":
                    cache.data += cache.decipher.final("binary");
                    if (encoding === 'text')
                        cache.data = trusted.Utf8.fromDer(cache.data);
                    resolve(cache.data);
                    break;
                default:
                    reject(err_t + "Unknown crypto module");
            }
        });
    };

    function init(args) {
        var err_t = "Decipher.init: ";
        var algorithm, key, psw, iv;
        switch (args.length) {
            case 2:
                algorithm = args[0];
                psw = args[1];
                // Check psw (STRING)
                if (!trusted.isString(psw))
                    throw err_t + "Parameter 'password' must be type of String";
                break
            case 3:
                algorithm = args[0];
                key = args[1];
                iv = args[2];
                // Check key (DER STRING | PrivateKey)
                if (trusted.isObject(key)) {
                    if (key.type !== "PrivateKey")
                        throw err_t + "Parameter 'key' must be type of PrivateKey";
                    // PrivateKey to DER
                    key = key.export();
                } else if (!trusted.isString(key))
                    throw err_t + "Parameter 'key' must be type of String";
                // Check iv (DER STRING)
                if (!trusted.isString(iv))
                    throw err_t + "Parameter 'iv' must be type of String";
                break
            default:
                throw err_t + "Has wrong number of parameters";
        }
        // Check algorithm ( STRING | OBJECT::Algorithm)
        if (!trusted.isObject(algorithm))
            try {
                algorithm = new trusted.PKI.Algorithm.fromName(algorithm);
            } catch (e) {
                throw err_t + "Error on creating algorithm. " + e;
            }
        if (algorithm.type !== "Algorithm")
            throw err_t + "Parameter 'algorithm' must be type of Algorithm"

        cache = {};

        switch (trusted.Crypto.type) {
            case "webcrypto":

                break;
            case "nodejs":
                switch (args.length) {
                    case 2:
                        cache.decipher = require("crypto").createDecipher(algorithm.toCrypto(), psw);
                        break;
                    case 3:
                        cache.decipher = require("crypto").createDecipheriv(algorithm.toCrypto(), key, iv);
                        break;
                }
                break;
            default:
                throw err_t + "Unknown crypto module";
        }
    }

    init.call(this, arguments);
}
trusted.Crypto = new Crypto();
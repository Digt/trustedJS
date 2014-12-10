(function() {

    function PublicKey() {
        var obj, alg;

        this.__proto__ = {
            set algorithm(v) {
            },
            get algorithm() {
                if (alg === undefined)
                    alg = new trusted.PKI.Algorithm(obj.algorithm);
                return alg;
            },
            set key(v) {
            },
            get key() {
                return obj.subjectPublicKey;
            },
            get type() {
                return "PublicKey";
            }
        };

        this.__proto__.encode = function() {
            var key = this.toObject();
            return trusted.ASN.fromObject(key, "SubjectPublicKeyInfo").blob();
        };

        this.__proto__.export = function(format) {
            var err_t = "PublicKey.export: ";
            if (format === undefined) {
                throw err_t + "Parameter 'format' can't be Undefined";
            }
            switch (format) {
                case trusted.ExportType.binary:
                    return this.encode();
                    break;
                case trusted.ExportType.hex:
                    return Der.toHex(this.encode());
                    break;
                case trusted.ExportType.pem:
                    return Base64.format(Base64.fromDer(this.encode()), "public key");
                    break;
                default:
                    throw err_t + "Unknown export format";
            }
        };

        this.__proto__.toString = function() {
            var res = '';
            switch (this.algorithm.OID.value) {
                case "1.2.840.113549.1.1.1":
                    var asn = new trusted.ASN(this.key.encoded);
                    var RSAPublicKey = asn.toObject("RSAPublicKey");
                    var r = /(00)*([A-F0-9]+)/i;
                    var m = r.exec(RSAPublicKey.modulus);
                    res = " (" + (((m[m.length - 1].length) / 2) * 8) + " Bits)";
                    break;
                case "1.2.643.2.2.19":
                    var asn = new trusted.ASN(this.key.encoded);
                    var GOSTPublicKey = asn.toObject("GOSTPublicKey");
                    res = " (" + (((GOSTPublicKey.length) / 2) * 8) + " Bits)";
                    break;
                default:
                    res = this.key.toString();
            }
            return this.algorithm.OID.toString() + res;
        };

        this.__proto__.toObject = function() {
            var o = {
                algorithm: this.algorithm.toObject(),
                subjectPublicKey: this.key
            };
            return o;
        };

        this.__proto__.equals = function(publicKey) {
            if (publicKey === undefined || publicKey.type !== "PublicKey")
                throw "PublicKey.equals: Параметр должен быть PublicKey"
            return this.toString() === publicKey.toString();
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "PublicKey.new: parameter can not be undefined."
            v = objFromBuffer(v, "AlgorithmIdentifier");
            if (!((trusted.isObject(v)) && ("algorithm" in v) && ("subjectPublicKey" in v)))
                throw "PublicKey.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.PublicKey = PublicKey;

    function PrivateKey() {
        var key, alg;

        this.__proto__ = {
            get algorithm() {
                if (alg === undefined)
                    alg = new trusted.PKI.Algorithm(alg);
                return alg;
            },
            get key() {
                return key;
            },
            get type() {
                return "PrivateKey";
            }
        };

        /*
         * Exports key in PrivateKeyInfo
         */
        this.__proto__.export = function(format) {
            var err_t = "PublicKey.export: ";
            if (format === undefined) {
                format = trusted.ExportType.binary;
            }
            var res = trusted.PKI.PrivateKeyInfo.create(this.algorithm, key);
            switch (format) {
                case trusted.ExportType.binary:
                    return res;
                case trusted.ExportType.hex:
                    return res.toString("hex");
                case trusted.ExportType.pem:
                    return res.toString("base64");
                default:
                    throw err_t + "Unknown export format";
            }
        };

        this.__proto__.toPKCS8 = function(algorithm) {
            if (algorithm === undefined)
                algorithm = this.algorithm;
            else
            if (trusted.isString(algorithm))
                algorithm = trusted.PKI.Algorithm.fromName(algorithm);

            var pkcs8 = {
                version: 0,
                algorithm: algorithm.toObject(),
                key: key
            };
            return trusted.ASN.fromObject(pkcs8, "PKCS8").blob();
        };

        function init(v, a) {
            var err_t = "PrivateKey.new: ";
            // Проверка аргумента
            if (v === undefined || a === undefined)
                throw err_t + "Parameter can not be undefined.";
            v = objFromBuffer(v, "ANY");
            if (trusted.isString(a))
                a = trusted.PKI.Algorithm.fromName(a);
            if (a.type !== "Algorithm")
                throw err_t + "Parameter 'algorithm' must be type of Algorithm";
            key = v;

            alg = a;
        }

        init.call(this, arguments[0], arguments[1]);
    }

    trusted.PKI.PrivateKey = PrivateKey;

    function KeyPair() {

        this.__proto__ = {
            set mediaName(v) {
            },
            get mediaName() {
            },
            set name(v) {
            },
            get name() {
            },
            set path(v) {
            },
            get path() {
            },
            set privateKey(v) {
            },
            get privateKey() {
            },
            set publicKey(v) {
            },
            get publicKey() {
            },
            set mediaType(v) {
            },
            get mediaType() {
            }
        };

        function init(args) {

        }

        init.call(this, arguments);
    }

    trusted.PKI.PrivateKey = PrivateKey;


    function PrivateKeyInfo() {
        var _obj;

        this.__proto__ = {
            get version() {
                return _obj.version.toNumber();
            },
            get algorithm() {
                return new trusted.PKI.Algorithm(_obj.privateKeyAlgorithm);
            },
            get content() {
                return _obj.privateKey;
            },
            get attributes() {
                if (_obj.attributes === null)
                    return [];
                var res = [];
                for (var i in _obj.attributes)
                    res.push(new trusted.PKI.Attribute(_obj.attributes[i]));
                return res;
            },
            get type() {
                return "PrivateKeyInfo";
            }
        };

        this.__proto__.getAttribute = function(oid) {
            if (trusted.isString(oid))
                oid = new trusted.PKI.OID(oid);
            for (var i in this.attributes)
                if (this.attributes[i].type.value === oid.value)
                    return this.attributes[i];
            return null;
        };

        this.__proto__.encrypt = function(pass, alg) {
            if (alg.type !== "Algorithm")
                throw this.type + ".encrypt: parameter alg must be type of Algorithm."
            var derAlg = trusted.ASN.fromObject(alg.toObject(), "AlgorithmIdentifier").blob();
            var derPKI = trusted.ASN.fromObject(this.toObject(), "PrivateKeyInfo").blob();
            return trusted.Crypto.pkcs12.encrypt(pass, derAlg, derPKI);
        };

        this.__proto__.toObject = function() {
            if (_obj !== undefined)
                return _obj;
        };

        function init(args) {
            _obj = objFromBuffer(args[0], "PrivateKeyInfo");
        }

        init.call(this, arguments);
    }

    PrivateKeyInfo.create = function(alg, content, attrs) {
        if (trusted.isString(alg))
            alg = trusted.PKI.Algorithm.fromName(alg);
        if (alg.type !== "Algorithm")
            throw "PrivateKeyInfo.create: Parameter 1 must be type of Algorithm";
        var pki = {
            version: 0,
            privateKeyAlgorithm: alg.toObject(),
            privateKey: content,
            attributes: []
        };
        if (attrs !== undefined) {
            if (!trusted.isArray(attrs))
                attrs = [attrs];
            for (var i in attrs)
                pki.attributes.push(attrs[i]);
        }
        return trusted.ASN.fromObject(pki, "PrivateKeyInfo").blob();
    };

    trusted.PKI.PrivateKeyInfo = PrivateKeyInfo;

    function EncryptedPrivateKey() {
        var _obj;

        this.__proto__ = {
            get algorithm() {
                return new trusted.PKI.Algorithm(_obj.encryptionAlgorithm);
            },
            get content() {
                return _obj.encryptedData;
            },
            get type() {
                return "EncyptedPrivateKey";
            }
        };
        
        this.toObject=function(){
            return _obj;
        };

        function init(args) {
            _obj = objFromBuffer(args[0], "EncryptedPrivateKeyInfo");
        }

        this.__proto__.decrypt = function(pass) {
            var alg = this.algorithm.toObject();
            console.log("Algorithm:", alg);
            //alg.algorithm = "1.2.840.113549.1.12.1.3";
            var derAlg = trusted.ASN.fromObject(alg, "AlgorithmIdentifier").blob();
            
            return trusted.Crypto.pkcs12.decrypt(derAlg, pass, this.content);
        };

        init.call(this, arguments);
    }

    EncryptedPrivateKey.create = function(alg, pass, content, attrs) {
        var pki = PrivateKeyInfo.create(alg, content, attrs);

        var params = trusted.ASN.fromObject(
                {
                    salt: trusted.Crypto.randomBytes(8),
                    iterations: 2000
                },
        "PBEParams"
                ).blob();
        var x509_alg = trusted.ASN.fromObject(
                {
                    algorithm: "1.2.840.113549.1.12.1.3",
                    parameters: params
                },
        "AlgorithmIdentifier"
                ).blob();
        
        var algObj = new trusted.PKI.Algorithm(x509_alg);
        var encData = trusted.Crypto.pkcs12.encrypt(algObj.encode(), pass, pki);

        var epki = {
            encryptionAlgorithm: algObj.toObject(),
            encryptedData: encData
        };
        return trusted.ASN.fromObject(epki, "EncryptedPrivateKeyInfo").blob();
    };

    trusted.PKI.EncryptedPrivateKey = EncryptedPrivateKey;
})();
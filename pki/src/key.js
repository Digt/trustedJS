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
            return trusted.ASN.fromObject(key, "SubjectPublicKeyInfo").encode();
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

        this.__proto__.export = function(format) {
            var err_t = "PublicKey.export: ";
            if (format === undefined) {
                format=trusted.ExportType.binary;
            }
            switch (format) {
                case trusted.ExportType.binary:
                    return this.key;
                    break;
                case trusted.ExportType.hex:
                    return Der.toHex(this.key);
                    break;
                case trusted.ExportType.pem:
                    var keyName = "";
                    switch (this.algorithm.OID.value) {
                        case "1.2.840.113549.1.1.1":
                        case "1.2.840.113549.1.1.2":
                        case "1.2.840.113549.1.1.3":
                        case "1.2.840.113549.1.1.4":
                        case "1.2.840.113549.1.1.5":
                        case "1.2.840.113549.1.1.11":
                        case "1.2.840.113549.1.1.12":
                        case "1.2.840.113549.1.1.13":
                        case "1.2.840.113549.1.1.14":
                            keyName = "rsa ";
                            break;
                    }
                    return Base64.format(Base64.fromDer(key), keyName + "private key");
                    break;
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
            return trusted.ASN.fromObject(pkcs8, "PKCS8").encode();
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

    function KeyPair(){
        
        this.__proto__ = {
            set mediaName(v){},
            get mediaName(){},
            set name(v){},
            get name(){},
            set path(v){},
            get path(){},
            set privateKey(v){},
            get privateKey(){},
            set publicKey(v){},
            get publicKey(){},
            set mediaType(v){},
            get mediaType(){}
        };
        
        function init(args){
            
        }
        
        init.call(this, arguments);
    }
    
    trusted.PKI.PrivateKey = PrivateKey;
})();
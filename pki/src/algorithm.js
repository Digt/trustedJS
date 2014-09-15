trusted.RegisteredAlgorithms = {
    "RSAES-PKCS1-v1_5": {
        encrypt: true,
        decrypt: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "RSASSA-PKCS1-v1_5": {
        sign: true,
        verify: true,
        generateKey: true,
        importKey: true,
        exportKey: true
    },
    "RSA-PSS": {
        sign: true,
        verify: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "RSA-OAEP": {
        encrypt: true,
        decrypt: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "ECDSA": {
        sign: true,
        verify: true,
        generateKey: true,
        importKey: true,
        exportKey: true
    },
    "ECDH": {
        generateKey: true,
        deriveKey: true,
        deriveBits: true,
        importKey: true,
        exportKey: true
    },
    "AES-CTR": {
        encrypt: true,
        decrypt: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "AES-CBC": {
        encrypt: true,
        decrypt: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "AES-CMAC": {
        sign: true,
        verify: true,
        generateKey: true,
        importKey: true,
        exportKey: true
    },
    "AES-GCM": {
        encrypt: true,
        decrypt: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "AES-CFB": {
        encrypt: true,
        decrypt: true,
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "AES-KW": {
        generateKey: true,
        importKey: true,
        exportKey: true,
        wrapKey: true,
        unwrapKey: true
    },
    "HMAC": {
        sign: true,
        verify: true,
        generateKey: true,
        importKey: true,
        exportKey: true
    },
    "DH": {
        generateKey: true,
        deriveKey: true,
        deriveBits: true,
        importKey: true,
        exportKey: true
    },
    "SHA-1": {
        digest: true
    },
    "SHA-256": {
        digest: true
    },
    "SHA-384": {
        digest: true
    },
    "SHA-512": {
        digest: true
    },
    "CONCAT": {
        deriveKey: true,
        deriveBits: true
    },
    "HKDF-CTR": {
        deriveKey: true,
        deriveBits: true
    },
    "PBKDF2": {
        deriveKey: true,
        deriveBits: true
    }
};

trusted.RegisteredAlgorithms.getAlgorithms = function(usage) {
    var algs = {};
    trusted.objEach(trusted.RegisteredAlgorithms, function(v, n) {
        if (usage in v)
            algs[n] = v;
    });
    return algs;
};

(function() {
    function Algorithm() {
        var obj;
        var cache;
        var alg;

        this.__proto__ = {
            set OID(v) {
            },
            get OID() {
                if (alg === undefined)
                    alg = new trusted.PKI.OID(obj.algorithm);
                return alg;
            },
            get name() {
                return this.OID.name;
            },
            get params() {
                if (this.hasParams() && obj.parameters !== Hex.toDer("0500"))
                    return obj.parameters;
                return null;
            },
            get crypto() {
                var o = {name: "RSASSA-PKCS1-v1_5", hash: {}};
                switch (this.OID.value) {
                    case "1.2.840.113549.1.1.1":
                    case "1.2.840.113549.1.1.5":
                        o.hash.name = "SHA-1";
                        break;
                    case "1.2.840.113549.1.1.11":
                        o.hash.name = "SHA-256";
                        break;
                    case "1.2.840.113549.1.1.12":
                        o.hash.name = "SHA-384";
                        break;
                    case "1.2.840.113549.1.1.13":
                        o.hash.name = "SHA-512";
                        break;
                    default:
                        throw "Algorithm.crypto: " + this.name + " алгоритм не поддерживается."
                }
                return o;
            }
        };

        this.__proto__.hasParams = function() {
            return obj.parameters !== undefined;
        };

        this.__proto__.toString = function() {
            return this.OID.name;
        };

        this.__proto__.toObject = function() {
            var o = {
                algorithm: this.OID.toObject(),
                parameters: (Der.toHex(this.params) === "0500" ? Hex.toDer("0500") : this.params),
                name: this.name,
                hash: {name: this.hash}
            };
            return o;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "Algorithm.new: parameter can not be undefined."
            cache = {};
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("AlgorithmIdentifier");
            }
            if (!((trusted.isObject(v)) && ("algorithm" in v)))
                throw "Algorithm.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.Algorithm = Algorithm;
})();

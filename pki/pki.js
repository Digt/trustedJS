(function(){

if (window.trusted===undefined)
    throw "Для работы модуля PKI необходим модуль trusted.js";

if (trusted.ASN===undefined)
    throw "Для работы модуля PKI необходим модуль ASN";if (window.trusted === undefined)
    window.trusted = {};

trusted.PKI = {};

trusted.ExportType = {
  binary: 1,  
  hex: 2,  
  pem: 3  
};

/**
 * Возвращает объект полученный из буфера по заданной схеме.
 * @param {type} buf Буфер. Параметр может быть двух типов - бинарная строка и Буфер.
 * @param {type} schemaName Имя схемы.
 * @returns {Object}
 */
function objFromBuffer(buf, schemaName){
    if (trusted.isString(buf))
        buf = new trusted.Buffer(buf, "binary");
    if (buf.type!=="Buffer")
        return buf;
    var asn = new trusted.ASN(buf);
    var obj = asn.toObject(schemaName);
    return obj;
}

function getExtnByOID(extns, oid) {
    if (trusted.isString(oid))
        oid = new trusted.PKI.OID(oid);
    if (!(trusted.isObject(oid)) || oid === undefined)
        throw "Certificate.getExtnByOID: Параметр oid имеет неверное значение";
    var res = null;
    for (var i = 0; i < extns.length; i++) {
        if (extns[i].OID.value === oid.value)
            return extns[i];
    }
    return res;
}

// private
function Time() {
    var obj;
    function init(v){
        if (v===undefined)
            throw "Time.new: Парметр не может быть Undefined";
        if (trusted.isString(v)){
            var asn = new trusted.ASN(v);
            v = asn.toObject("Time");
        }
        if (!(trusted.isObject(v) && ("utcTime" in v || "generalTime" in v )))
            throw "Time.new: Парметр имеет неверный формат";
        obj = v;            
    }
    
    init.call(this, arguments[0]);
    
    if ("utcTime" in obj)
        obj = obj.utcTime;
    else
        obj = obj.generalTime;
    return  obj;
};(function() {
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
                if (obj.name !== undefined)
                    return obj.name;
                return this.OID.name;
            },
            get hash() {
                if (cache.hash === undefined) {
                    cache.hash = null;
                    if (obj.hash !== undefined)
                        cache.hash = Algorithm.fromName(obj.hash);
                }
                return cache.hash;
            },
            get params() {
                if (this.hasParams() && obj.parameters !== Hex.toDer("0500"))
                    return obj.parameters;
                return null;
            },
            get type() {
                return "Algorithm";
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
                //name: this.name,
                //hash: {name: this.hash}
            };
            return o;
        };

        this.__proto__.toCrypto = function() {
            var err_t = "Algorithm.toCrypto: ";
            switch (trusted.Crypto.type) {
                case "webcrypto":
                    var a = trusted.Algorithms.getAlgorithm(this.name);
                    var o = {
                        name: a.n.wc
                    };
                    if ("h" in a)
                        o.hash = {name: a.h.n.wc};
                    return o;
                case "nodejs":
                    return trusted.Algorithms.getAlgorithm(this.name).n.njs;
                default:
                    throw err_t + "Unknown algorithm type";
            }
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "Algorithm.new: parameter can not be undefined."
            cache = {};
            v = objFromBuffer(v, "AlgorithmIdentifier");
            if (!((trusted.isObject(v)) && ("algorithm" in v)))
                throw "Algorithm.new: parameter is not valid."
            try {
                var alg = AlgorithmFromOID(v.algorithm);
                if (alg !== null)
                    v = alg;
            } catch (e) {
                console.error(e);

            }
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    AlgorithmFromName = function(name) {
        var err_t = "Algorithm.fromName: ";
        if (name === undefined)
            throw err_t + "Parameter 'name' can't be undefined"
        var a = trusted.Algorithms.getAlgorithm(name);
        var o = {
            algorithm: a.o,
            parameters: null,
            name: a.n.f
        };
        if ("h" in a) // has hash algorithm
            o.hash = a.h.n.f;
        return o;
    };

    Algorithm.fromName = function(name) {
        return new Algorithm(AlgorithmFromName(name));
    };

    function AlgorithmFromOID(oid) {
        var err_t = "Algorithm.fromOID: ";
        if (!trusted.isObject(oid))
            oid = new trusted.PKI.OID(oid);
        if (oid.type !== "OID")
            throw err_t + "Parameter 'oid' must be OID type"
        var keys = Object.keys(trusted.Algorithms);
        for (var i = 0; i < keys.length; i++) {
            var alg = trusted.Algorithms[keys[i]];
            if (typeof (alg) !== "function" && trusted.isObject(alg))
                if (alg.o === oid.value)
                    return AlgorithmFromName(keys[i]);
        }
        return null;
    }

    Algorithm.fromOID = function(oid) {
        return new Algorithm(AlgorithmFromOID(oid));
    };

    trusted.PKI.Algorithm = Algorithm;
})();
/*
 * List of algorithms. It has WebCryto and OpenSSL algorithms
 * u: Usage:
 *    e: encrypt,
 *    d: dycrypt,
 *    s: sign,
 *    v: verify,
 *    dg: digest,
 *    gk: generate key,
 *    ik: import key,
 *    ek: export key,
 *    dk: derive key,
 *    db: derive bits,
 *    wk: wrap key,
 *    unwk: unwrap key
 * o: OID
 * n: name
 *   f: friendly name
 *   wc: WebCrypto
 *   nj: NodeJS 
 */

trusted.Algorithms = {
    //SHA
    "sha1": {u: ["dg"], o: "1.3.14.3.2.26", n: {f: "SHA1", wc: "sha-1", njs: "sha1"}},
    "sha224": {u: ["dg"], o: "2.16.840.1.101.3.4.2.4", n: {f: "SHA224", njs: "sha224"}},
    "sha256": {u: ["dg"], o: "2.16.840.1.101.3.4.2.1", n: {f: "SHA256", wc: "sha-256", njs: "sha256"}},
    "sha384": {u: ["dg"], o: "2.16.840.1.101.3.4.2.2", n: {f: "SHA384", wc: "sha-384", njs: "sha384"}},
    "sha512": {u: ["dg"], o: "2.16.840.1.101.3.4.2.3", n: {f: "SHA512", wc: "sha-512", njs: "sha512"}},
    //MD
    "md4": {u: ["dg"], o: "1.2.840.113549.2.4", n: {f: "MD4", njs: "md4"}},
    "md5": {u: ["dg"], o: "1.2.840.113549.2.5", n: {f: "MD5", njs: "md5"}},
    //RSA
    "rsa": {u: ["e", "d", "gk", "ik", "ek", "wk", "unwk"], o: "1.2.840.113549.1.1.1", n: {f: "RSA", njs: "rsa", wc: "RSAES-PKCS1-v1_5"}},
    "rsaencryption": "rsa",
    "rsa-md4": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.3", h: "md4", n: {f: "RSA-MD4", njs: "RSA-MD4"}},
    "rsa-md5": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.4", h: "md5", n: {f: "RSA-MD5", njs: "RSA-MD5"}},
    "rsa-sha1": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.5", h: "sha1", n: {f: "RSA-SHA1", njs: "RSA-SHA1", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-oaep": {u: ["e", "d", "gk", "ik", "ek", "wk", "unwk"], o: "1.2.840.113549.1.1.7", n: {f: "RSA-OAEP", njs: "rsaOAEP", wc: "RSA-OAEP"}},
    "rsaoaep": "rsa-oaep",
    "rsa-sha256": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.11", h: "sha256", n: {f: "RSA-SHA256", njs: "RSA-SHA256", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-sha384": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.12", h: "sha384", n: {f: "RSA-SHA384", njs: "RSA-SHA384", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-sha512": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.13", h: "sha512", n: {f: "RSA-SHA512", njs: "RSA-SHA512", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-sha224": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.14", h: "sha224", n: {f: "RSA-SHA224", njs: "RSA-SHA224"}},
    "rsa-pss": {u: ["gk", "ik", "ek"], o: "1.2.840.113549.1.1.10", n: {f: "RSA-PSS", njs: "rsaPSS", wc: "RSA-PSS"}},
    //AES
    //AES-CBC
    "aes128-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "2.16.840.1.101.3.4.1.2", n: {f: "AES128-CBC", njs: "aes-128-cbc", wc: "aes-cbc"}},
    "aes128":"aes128-cbc",
    "aes192-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "2.16.840.1.101.3.4.1.22", n: {f: "AES192-CBC", njs: "aes-192-cbc", wc: "aes-cbc"}},
    "aes192":"aes192-cbc",
    "aes256-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "2.16.840.1.101.3.4.1.42", n: {f: "AES256-CBC", njs: "aes-256-cbc", wc: "aes-cbc"}},
    "aes256":"aes256-cbc",
    //RC2
    "rc2-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "1.2.840.113549.3.2", n: {f: "RC2-CBC", njs: "rc2-cbc"}},
    "rc2": "rc2-cbc"
};

trusted.AlgorithmUsage = {
    encrypt: "e",
    decrypt: "d",
    sign: "s",
    verify: "v",
    digest: "dg",
    generateKey: "gk",
    importKey: "ik",
    exportKey: "ek",
    deriveKey: "dk",
    deriveBits: "db",
    wrapKey: "wk",
    unwrapKey: "unwk"
};

trusted.Algorithms.select = function(usage) {
    var err_t = "Algorithms.getAlgorithms: ";
    if (usage !== undefined) {
        if (!trusted.isArray(usage))
            usage = [usage];
        for (var i = 0; i < usage.length; i++) {
            if (!trusted.isString(usage[i]))
                throw err_t + "Parameter 'usage' has wrong data type."
            if (!(usage[i] in trusted.AlgorithmUsage))
                throw err_t + "Parameter 'usage' uses unknown algorithm usage '" + usage[i] + "'."
        }
    }

    var algs = [];
    var type = trusted.Crypto.type;
    switch (type) {
        case "webcrypto":
            type = "wc";
            break;
        case "nodejs":
            type = "njs";
            break;
        default:
            throw err_t + "Unknown trusted.Crypto type"
    }
    trusted.objEach(trusted.Algorithms, function(v, n) {
        if ((typeof (v) === "function"))
            return;
        if (trusted.isString(v))
            return;
        if (usage === undefined) {
            if (type in v.n)
                algs.push(trusted.Algorithms.getAlgorithm(n).n.f);
        }
        else {
            for (var i = 0; i < usage.length; i++) {
                if (type in v.n) {
                    if (v.u.indexOf(trusted.AlgorithmUsage[usage[i]]) > -1) {
                        algs.push(trusted.Algorithms.getAlgorithm(n).n.f);
                        break;
                    }
                }
            }
        }
    });
    return algs;
};

trusted.Algorithms.getAlgorithm = function(name) {
    var err_t = "Algorithms.getAlgorithm: ";
    if (name === undefined)
        throw err_t + "Parameter 'name' can't be undefined"
    if (!trusted.isString(name))
        throw err_t + "Parameter 'name' must be String"
    name = name.toLowerCase();
    if (!(name in trusted.Algorithms))
        throw err_t + "'" + name + "' is unknown algorithm name";
    var type = trusted.Crypto.type;
    switch (type) {
        case "webcrypto":
            type = "wc";
            break;
        case "nodejs":
            type = "njs";
            break;
        default:
            throw err_t + "Unknown trusted.Crypto type"
    }
    var alg = trusted.Algorithms[name];
    if (trusted.isString(alg))
        alg = trusted.Algorithms.getAlgorithm(alg);
    if (!(type in alg.n))
        throw err_t+"Algorithm '"+name+"' is not supported"
    if ("h" in alg && !trusted.isObject(alg.h)) {
        alg.h = trusted.Algorithms.getAlgorithm(alg.h);
    }
    return alg;
};(function(undefined) {
    function Certificate() {
        var obj;
        var cache;

        this.__proto__ = {
            get type() {
                return "Certificate";
            },
            set version(v) {
            },
            get version() {
                return obj.tbsCertificate.version.toNumber();
            },
            set serialNumber(v) {
            },
            get serialNumber() {
                return obj.tbsCertificate.serialNumber;
            },
            set notBefore(v) {
            },
            get notBefore() {
                return (obj.tbsCertificate.validity.notBefore.utcTime === undefined)
                        ? obj.tbsCertificate.validity.notBefore.generalTime
                        : obj.tbsCertificate.validity.notBefore.utcTime;
            },
            set notAfter(v) {
            },
            get notAfter() {
                return (obj.tbsCertificate.validity.notAfter.utcTime === undefined)
                        ? obj.tbsCertificate.validity.notAfter.generalTime
                        : obj.tbsCertificate.validity.notAfter.utcTime;
            },
            set TBSCertificate(v) {
            },
            get TBSCertificate() {
                return cache.asn.sub[0].blob();
            },
            set subjectName(v) {
            },
            get subjectFriendlyName() {
                if (cache.sfn === undefined) {
                    cache.sfn = null;
                    var attrs = this.subjectName.getAttributes("2.5.4.3");
                    if (attrs.length > 0)
                        cache.sfn = attrs[0].text;
                }
                return cache.sfn;
            },
            get subjectName() {
                if (cache.sn === undefined) { //cache
                    cache.sn = new trusted.PKI.Name(obj.tbsCertificate.subject);
                }
                return cache.sn;
            },
            set issuerName(v) {
            },
            get issuerName() {
                if (cache.isn === undefined) { //cache
                    cache.isn = new trusted.PKI.Name(obj.tbsCertificate.issuer);
                }
                return cache.isn;
            },
            get issuerFriendlyName() {
                if (cache.ifn === undefined) {
                    cache.ifn = null;
                    var attrs = this.issuerName.getAttributes("2.5.4.3");
                    if (attrs.length > 0)
                        cache.ifn = attrs[0].text;
                }
                return cache.ifn;
            },
            set signatureAlgorithm(v) {
            },
            get signatureAlgorithm() {
                if (cache.salg === undefined) { //cache
                    cache.salg = new trusted.PKI.Algorithm(obj.tbsCertificate.signature);
                }
                return cache.salg;
            },
            set signature(v) {
            },
            get signature() {
                return obj.signature;
            },
            set publicKey(v) {
            },
            get publicKey() {
                if (cache.pk === undefined) {
                    cache.pk = new trusted.PKI.PublicKey(obj.tbsCertificate.subjectPublicKeyInfo);
                }
                return cache.pk;
            },
            set extensions(v) {
            },
            get extensions() {
                if (cache.extns === undefined) {
                    cache.extns = [];
                    if (obj.tbsCertificate.extensions !== null) {
                        var e = obj.tbsCertificate.extensions;
                        if (e !== undefined)
                            for (var i = 0; i < e.length; i++)
                                cache.extns.push(new trusted.PKI.Extension(e[i]));
                    }
                }
                return cache.extns;
            },
            set issuerUniqueID(v) {
            },
            get issuerUniqueID() {
                if (cache.iuid === undefined) {
                    cache.iuid = null;
                    if (obj.tbsCertificate.issuerUniqueID !== null)
                        cache.iuid = obj.tbsCertificate.issuerUniqueID;
                }
                return cache.iuid;
            },
            set subjectUniqueID(v) {
            },
            get subjectUniqueID() {
                if (cache.suid === undefined) {
                    cache.suid = null;
                    if (obj.tbsCertificate.subjectUniqueID !== null)
                        cache.suid = obj.tbsCertificate.subjectUniqueID;
                }
                return cache.suid;
            },
            get basicConstraints() {
                if (cache.bc === undefined) { // cache
                    cache.bc = this.getExtension("2.5.29.19");
                    if (cache.bc) {
                        cache.bc = new trusted.PKI.BasicConstraints(cache.bc.value);
                    }
                }
                return cache.bc;
            },
            get keyUsage() {
                if (cache.ku === undefined) { // cache
                    cache.ku = this.getExtension("2.5.29.15");
                    if (cache.ku) 
                        cache.ku = new trusted.PKI.KeyUsage(cache.ku.value);
                }
                return cache.ku;
            },
            get extendedKeyUsage() {
                if (cache.eku === undefined) { // cache
                    cache.eku = this.getExtension("2.5.29.37");
                    if (cache.eku) 
                        cache.eku = new trusted.PKI.ExtendedKeyUsage(cache.eku.value);
                }

                return cache.eku;
            },
            get issuerAlternativeName() {
                if (cache.ian === undefined) { // cache
                    cache.ian = this.getExtension("2.5.29.18");
                    if (cache.ian) 
                        cache.ian = new trusted.PKI.IssuerAlternativeName(cache.ian.value);
                }
                return cache.ian;
            },
            get subjectAlternativeName() {
                if (cache.san === undefined) { // cache
                    cache.san = this.getExtension("2.5.29.17");
                    if (cache.san) {
                        cache.san = new trusted.PKI.SubjectAlternativeName(cache.san.value);
                    }
                }
                return cache.san;
            }
        };

        this.__proto__.isSelfSigned = function() {
            return this.subjectName.toString() === this.issuerName.toString();
        };

        this.__proto__.verify = function(issuerCert) {
            var err_t = "Certificate.verify: ";
            var key = null;
            var key;
            if (issuerCert === undefined) {
                if (!this.isSelfSigned())
                    return Promise.reject(err_t + "Необходим открытый ключ сертификата издателя.");
                else
                    key = this.publicKey;
            } else {
                switch (issuerCert.type) {
                    case "Certificate":
                        key = issuerCert.publicKey;
                        break;
                    case "PublicKey":
                        key = issuerCert;
                        break;
                    default:
                        return Promise.reject(err_t + "Параметр не известного типа");
                }
            }

            var verifier = trusted.Crypto.createVerify(this.signatureAlgorithm);
            verifier.update(this.TBSCertificate);
            return verifier.verify(this.publicKey, this.signature.encoded);
        };

        this.__proto__.getHash = function(alg) {
            if (alg === undefined) {
                alg = "sha1";
            }
            var hash = new trusted.Crypto.createHash(alg);
            hash.update(this.encode());
            return hash.digest();
        };

        this.__proto__.encode = function() {
            if (cache.asn !== undefined) {
                return cache.asn.blob();
            }
            return null;
        };

        this.__proto__.toObject = function() {
            var o = {
                signatureAlgorithm: this.signatureAlgorithm.toObject(),
                signature: this.signature
            };
            o.tbsCertificate = {
                version: this.version,
                serialNumber: this.serialNumber,
                signature: this.signatureAlgorithm.toObject(),
                issuer: this.issuerName.toObject(),
                validity: {
                    notBefore: {utcTime: this.notBefore},
                    notAfter: {utcTime: this.notAfter}
                },
                subject: this.subjectName.toObject(),
                subjectPublicKeyInfo: this.publicKey.toObject(),
                issuerUniqueID: this.issuerUniqueID,
                subjectUniqueID: this.subjectUniqueID
            };
            if (this.extensions.length !== 0) {
                o.tbsCertificate.extensions = [];
                for (var i = 0; i < this.extensions.length; i++) {
                    o.tbsCertificate.extensions.push(this.extensions[i].toObject());
                }
            }
            return o;
        };

        /**
         * Возвразает коллекцию расширений сертификата.
         * @param {String|trusted.PKI.OID} oid
         * OID расширения
         * @returns {trusted.PKI.Extension}
         */
        this.__proto__.getExtension = function(oid) {
            if (!(oid === undefined || this.extensions === null))
                return getExtnByOID(this.extensions, oid); // Возвращает Extension или null
            return null;
        };

        this.__proto__.import = function() {
            cache = {}; // clear cashe
            var cert = arguments[0];
            if (trusted.isString(cert)) {
                //проверка входных данных
                var der = cert;
                try { //try Base64
                    if (Base64.re.test(der))
                        der = Base64.unarmor(der);
                    else
                        der = Base64.toDer(der);
                }
                catch (e) { //try Hex
                    try {
                        der = Hex.toDer(der);
                    }
                    catch (e) {
                    }
                }
                var asn = new trusted.ASN(der);
                cert = asn.toObject("Certificate");

                cache.tbs = asn.structure.sub[0].encode();
                cache.encoded = asn.encode();
            }
            if (!trusted.isObject(cert))
                throw "Certificate.import: Параметр имеет неверный формат."
            obj = cert;
        };

        /**
         * Проверяет срок действия сертификата относительно заданной даты.
         * @param {Date} date Дата, относительно которой проверяется срок действия сертификата.
         * @returns {Boolean}
         */
        this.__proto__.checkValidity = function(date) {
            if (date === undefined)
                date = new Date();
            return (date >= this.notBefore && date <= this.notAfter);
        };

        this.__proto__.compare = function(cert) {
            if (cert.issuerName === undefined && cert.serialNumber === undefined)
                throw "Certificate.compare: Параметр имеет неверный формат."
            return (this.issuerName.toString() === cert.issuerName.toString() &&
                    this.serialNumber === cert.serialNumber);
        };

        function init(args) {
            cache = {};
            var cert = args[0];
            if (cert !== undefined) {
                if (trusted.isString(cert))
                    buf = new trusted.Buffer(buf, "binary");
                if (cert.type === "Buffer") {
                    var asn = new trusted.ASN(cert);
                    obj = asn.toObject("Certificate");

                    cache.asn = asn;
                    return;
                }

                //
                this.import(cert);
            }
        }

        init.call(this, arguments);
    }

    trusted.PKI.Certificate = Certificate;
})();(function() {

    function CRL() {
        var obj;
        var cache;
        var df_version = 1;

        this.__proto__ = {
            get type() {
                return "CRL";
            },
            get version() {
                if (obj.tbsCertList.version === null)
                    obj.tbsCertList.version = df_version;
                if (obj.tbsCertList.version !== df_version)
                    throw "CRL.version: Версия должна быть раавна 1."
                return obj.tbsCertList.version;
            },
            set version(v) {
            },
            get signatureAlgorithm() {
                if (cache.salg === undefined)
                    cache.salg = new trusted.PKI.Algorithm(obj.tbsCertList.signature);
                return cache.salg;
            },
            set signatureAlgorithm(v) {
            },
            get issuerName() {
                if (cache.issuer === undefined)
                    cache.issuer = new trusted.PKI.Name(obj.tbsCertList.issuer);
                return cache.issuer;
            },
            set issuerName(v) {
            },
            get thisUpdate() {
                return (obj.tbsCertList.thisUpdate.utcTime === undefined)
                        ? obj.tbsCertList.thisUpdate.generalTime
                        : obj.tbsCertList.thisUpdate.utcTime;
            },
            set thisUpdate(v) {
            },
            get nextUpdate() {
                if (obj.tbsCertList.nextUpdate === null || obj.tbsCertList.nextUpdate === undefined)
                    return null;
                return (obj.tbsCertList.nextUpdate.utcTime === undefined)
                        ? obj.tbsCertList.nextUpdate.generalTime
                        : obj.tbsCertList.nextUpdate.utcTime;
            },
            set nextUpdate(v) {
            },
            get certificates() {
                if (cache.certs === undefined) {
                    cache.certs = [];
                    if (obj.tbsCertList.revokedCertificates !== null) {
                        var certs = obj.tbsCertList.revokedCertificates;
                        for (var i = 0; i < certs.length; i++)
                            cache.certs.push(new RevokedCertificate(certs[i]));
                    }
                }
                return cache.certs;
            },
            set certificates(v) {
            },
            get extensions() {
                if (cache.extns === undefined) {
                    cache.extns = [];
                    var extns = obj.tbsCertList.crlExtensions;
                    if (extns !== null) {
                        for (var i = 0; i < extns.length; i++)
                            cache.extns.push(new trusted.PKI.Extension(extns[i]));
                    }
                }
                return cache.extns;
            },
            set signature(v) {
            },
            get signature() {
                return obj.signatureValue;
            },
            set sequenceNumber(v) {
            },
            //return CRLNumber extension value
            get sequenceNumber() {
                if (cache.seqNum === undefined) {
                    cache.seqNum = null;
                    var ext = this.getExtension("2.5.29.20");
                    if (ext !== null)
                        cache.seqNum = (new trusted.PKI.CRLNumber(ext.value)).value;
                }
                return cache.seqNum;
            },
            set deltaNumber(v) {
            },
            //return BaseCRLNumber extension value
            get deltaNumber() {
                if (cache.delNum === undefined) {
                    cache.delNum = null;
                    var ext = this.getExtension("2.5.29.27");
                    if (ext)
                        cache.delNum = (new trusted.PKI.CRLNumber(ext.value)).value;
                }
                return cache.delNum;
            },
            set issuerAlternativeName(v) {
            },
            //return IssuerAlternativeName extension value ONLY  2.5.29.18
            get issuerAlternativeName() {
                if (cache.ian === undefined) {
                    cache.ian = null;
                    var extn = this.getExtension("2.5.29.18");
                    if (extn) {
                        var asn = new trusted.ASN(extn.value);
                        cache.ian = new trusted.PKI.IssuerAlternativeName(asn.toObject("IssuerAlternativeName2"));

                    }
                }
                return cache.ian;
            },
            set TBSCertList(v) {
            },
            get TBSCertList() {
                return cache.tbs;
            }
        };

        this.__proto__.verify = function(key) {
            var err_t = "CRL.verify: ";
            if (key === undefined) {
                return Promise.reject(err_t + "Необходим открытый ключ сертификата издателя.");
            } else {
                switch (key.type) {
                    case "Certificate":
                        key = key.publicKey;
                        break;
                    case "PublicKey":
                        break;
                    default:
                        return Promise.reject(err_t + "Параметр неизвестного типа");
                }
            }

            var verifier = trusted.Crypto.createVerify(this.signatureAlgorithm);
            verifier.update(this.TBSCertList);
            return verifier.verify(key, this.signature.encoded);
        };

        // check if certificate is in CRL list of certificates.
        this.__proto__.hasCertificate = function(cert) {
            var certs = this.certificates;
            // check for extn(2.5.29.28).indirectCRL
            var extn = this.getExtension("2.5.29.28");
            if (extn !== null)
                extn = new trusted.PKI.IssuingDistributionPoint(extn.value);
            var issuerName = null;
            if (extn === null || !extn.indirectCRL)
                issuerName = this.issuerName;
            for (var i = 0; i < certs.length; i++)
                if (cert.compare({
                    issuerName: (issuerName !== null ? issuerName.toString() : certs[i].issuerName.toString()),
                    serialNumber: certs[i].serialNumber
                }))
                    return true;
            return false;
        };

        this.__proto__.getExtension = function(oid) {
            if (!(oid === undefined || this.extensions === null))
                return getExtnByOID(this.extensions, oid); // Возвращает Extension или null
            return null;
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.tbsCertList = {
                version: this.version,
                signature: this.signatureAlgorithm.toObject(),
                issuer: this.issuerName.toObject(),
                thisUpdate: {generalTime: this.thisUpdate}
            };
            void (this.nextUpdate !== null) ? o.tbsCertLis.nextUpdate = {generalTime: this.nextUpdate} : null;
            if (this.certificates !== null) {
                var certs = [];
                for (var i = 0; i < this.certificates.length; i++)
                    certs.push(this.certificates[i].toObject());
                o.tbsCertList.revokedCertificates = certs;
            }
            if (this.extensions !== null) {
                var extns = [];
                for (var i = 0; i < this.extensions.length; i++)
                    extns.push(this.extensions[i].toObject());
                o.tbsCertList.crlExtensions = extns;
            }

            o.signatureAlgorithm = this.signatureAlgorithm.toObject();
            o.signatureValue = this.signature;

            return o;
        };


        // inicialization
        function init(v) {
            if (v === undefined)
                throw "CRL.new: Параметр не может быть Undefined";
            var asn = null;
            cache = {};
            cache.tbs = null;
            if (trusted.isString(v))
                v = new trusted.Buffer(v, "binary");
            asn = new trusted.ASN(v);
            v = asn.toObject("CertificateList");
            cache.tbs = asn.sub[0].blob();
            if (!(trusted.isObject(v) || (true)))
                throw "CRL.new: Задан неверный параметр.";
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    // RevokedCertificate
    function RevokedCertificate() {
        var obj;
        var cache;

        this.__proto__ = {
            get serialNumber() {
                return obj.userCertificate;
            },
            set serialNumber(v) {
            },
            get revocationDate() {
                return (obj.revocationDate.utcTime === undefined)
                        ? obj.revocationDate.generalTime
                        : obj.revocationDate.utcTime;
            },
            set revocationDate(v) {
            },
            get extensions() {
                if (cache.extns === undefined) {
                    cache.extns = [];
                    if (obj.crlEntryExtensions !== null) {
                        for (var i = 0; i < obj.crlEntryExtensions.length; i++)
                            cache.extns.push(new trusted.PKI.Extension(obj.crlEntryExtensions[i]));
                    }
                }
                return cache.extns;
            },
            set extensions(v) {
            },
            set invalidityDate(v) {
            },
            get invalidityDate() {
                if (cache.invd === undefined) {
                    cache.invd = null;
                    var ext = this.getExtension("2.5.29.24");
                    if (ext !== null) {
                        var r = new trusted.PKI.InvalidityDate(ext.value);
                        cache.invd = r.value;
                    }
                }
                return cache.invd;
            },
            set reason(v) {
            },
            get reason() {
                if (cache.reason === undefined) {
                    cache.reason = null;
                    var ext = this.getExtension("2.5.29.21");
                    if (ext !== null) {
                        var r = new trusted.PKI.ReasonCode(ext.value);
                        cache.reason = r.value;
                    }
                }
                return cache.reason;
            },
            set issuerName(v) {
            },
            get issuerName() {
                if (cache.issuer === undefined) {
                    cache.issuer = null;
                    var ext = this.getExtension("2.5.29.29");
                    if (ext !== null) {
                        var r = new trusted.PKI.CertificateIssuer(ext.value);
                        cache.issuer = r;
                    }
                }
                return cache.issuer;
            }
        };

        this.__proto__.getExtension = function(oid) {
            if (!(oid === undefined || this.extensions === null))
                return getExtnByOID(this.extensions, oid); // Возвращает Extension или null
            return null;
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.userCertificate = this.serialNumber;
            o.revocationDate = {generalTime: this.revocationDate};
            if (this.extensions !== null) {
                var extns = [];
                for (var i = 0; i < this.extensions.length; i++)
                    extns.push(this.extensions[i].toObject());
                o.crlEntryExtensions = extns;
            }

            return o;
        };

        // inicialization
        function init(v) {
            if (v === undefined)
                throw "RevokedCertificate.new: Параметр не может быть Undefined";
            v = objFromBuffer(v, "RevokedCertificate");
            if (!(trusted.isObject(v) || ("userCertificate" in v && "revocationDate" in v)))
                throw "RevokedCertificate.new: Задан неверный параметр.";

            obj = v;
            cache = {};
        }

        init.call(this, arguments[0]);
    }

    // export
    trusted.PKI.CRL = CRL;
    trusted.PKI.RevokedCertificate = RevokedCertificate;
})();trusted.CryptoStatus = {
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
trusted.Crypto = new Crypto();function CTL() {
    var sd, obj, cache;

    this.__proto__ = {
        get type() {
            return "CTL";
        },
        get version() {
            return obj.version;
        },
        get identifier() {
            return obj.listIdentifier;
        },
        get usage() {
            if (cache.usage === undefined) {
                cache.usage = [];
                var usage = obj.subjectUsage;
                for (var i = 0; i < usage.length; i++)
                    cache.usage.push(new trusted.PKI.OID(usage[i]));
            }
            return cache.usage;
        },
        get thisUpdate() {
            return Time(obj.thisUpdate);
        },
        get nextUpdate() {
            if (obj.nextUpdate !== null)
                return Time(obj.nextUpdate);
            else
                return null;
        },
        get sequenceNumber() {
            return obj.sequenceNumber;
        },
        get algorithm() {
            if (cache.alg === undefined) {
                cache.alg = new trusted.PKI.Algorithm(obj.subjectAlgorithm);
            }
            return cache.alg;
        },
        get certificates() {
            return sd.certificates;
        }
    };

    this.__proto__.getTrustCertificates = function(certs) {
        if (certs === undefined)
            return new Promise(function(res, rej) {
                ref("CTL.getCertificates: Параметр не может быть Undefined");
            });

        var trust_certs = [];
        var _this = this;
        var sequence = new Promise(function(resolve, reject) {
            for (var i = 0; i < certs.length; i++) {
                var p = _this.hasCertificate(certs[i]).then(
                        function(v) {
                            if (v) {
                                trust_certs.push(v.cert);
                            }
                        }
                );
                if (i === (certs.length - 1))
                    p.then(function() {
                        resolve(trust_certs);
                    });
            }
        });
        return sequence;
    };

    this.__proto__.hasCertificate = function(cert) {
        var sequence = cert.getHash(this.algorithm);

        sequence = sequence.then(
                function(v) {
                    var hashes = obj.subjects;
                    for (var i = 0; i < hashes.length; i++)
                        if (v === hashes[i].subjectIdentifier)
                            return new Promise(function(res, rej) {
                                res({result: true, cert: cert});
                            });
                    return new Promise(function(res, rej) {
                        res(false);
                    });
                },
                function(err) {
                    return new Promise(function(res, rej) {
                        rej(err);
                    });
                }
        );
        return sequence;
    };

    function init(args) {
        cache = {};
        switch (args.length) {
            case 0:
                throw "CTL.new: Параметр не может быть Undefined.";
            case 1:
                var v = args[0];
                sd = new SignedData(v);
                obj = objFromBuffer(v, "CertificateTrustList");
                break;
            default:
                throw "CTL.new: Параметр задан неверно.";
        }
    }

    init.call(this, arguments);
}
(function() {
    function Extension() {
        var obj;

        this.__proto__ = {
            set critical(v) {
            },
            get critical() {
                return (obj === undefined) ? undefined : obj.critical;
            },
            get value() {
                return (obj === undefined) ? undefined : obj.extnValue;
            },
            get OID() {
                return (obj === undefined) ? undefined : new trusted.PKI.OID(obj.extnID);
            },
            get type(){
                return "Extension";
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.critical = this.critical;
            o.extnID = this.OID.value;
            o.extnValue = this.value;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "Extension.new: parameter can not be undefined."
            v = objFromBuffer(v, "Extension");
            if (!(trusted.isObject(v) &&
                    "critical" in v &&
                    "extnID" in v &&
                    "extnValue" in v))
                throw "Extension.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.Extension = Extension;
})();



trusted.PKI.GeneralNameType = {
    OtherName: 0,
    RFC822Name: 1,
    DNSName: 2,
    X400Address: 3,
    DirectoryName: 4,
    EDIPartyName: 5,
    UniformResourceIdentifier: 6,
    IPAddress: 7,
    RegisteredID: 8
};

(function(undefined) {

    // <editor-fold defaultstate="collapsed" desc=" RDNAttribute ">
    function RDNAttribute() {
        var obj;
        this.__proto__ = {
            set type(v) {
            },
            get type() {
                return obj.type;
            },
            set OID(v) {
            },
            get OID() {
                return obj.type;
            },
            set value(v) {
            },
            get value() {
                return obj.value;
            },
            get text() {
                return valueToString(this.value, '+');
            }
        };

        this.__proto__.toObject = function() {
            return {type: this.type.value, value: this.value};
        };

        this.__proto__.format = function(seporator, oids) {
            if (trusted.isObject(seporator) && oids === undefined) {
                oids = seporator;
                seporator = undefined;
            }
            if (seporator === undefined)
                seporator = '+';
            var str = '';
            str = valueToString(this.value, seporator);
            var oidName = this.type.value; //Если oids задан, то использовать только его значения
            if (trusted.isObject(oids)) {
                if (oidName in oids)
                    oidName = oids[oidName];
            } else
                oidName = this.type.name;
            return  oidName + "=" + str;
        };
        this.__proto__.toString = function() {
            return this.format();
        };


        function valueToString(v, seporator) {
            var res = '';
            var asn = new trusted.ASN(v);
            if (asn.tag.isUniversal())
                if (!asn.tag.constructed) // Определение простого типа
                    res = asn.toValue();
                else {
                    for (var i = 0; i < asn.sub.length; i++) { // структуру выводим в виде массива через разделитель.
                        var content = asn.sub[i].content();
                        res += (i !== 0) ? seporator + content : content;
                    }
                }
            return res;
        }
        //Counstructor
        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "RDNAttribute.new: parameter can not be undefined."
            v = objFromBuffer(v, "AttributeTypeAndValue");
            if (typeof (v) !== "object" &&
                    !(v.hasOwnProperty("type") || v.hasOwnProperty("value")))
                throw "RDNAttribute.new: parameter is not valid."
            if (trusted.isString(v.type))
                v.type = new trusted.PKI.OID(v.type);
            obj = v;
        }


        init.call(this, arguments[0]);
    }
    trusted.PKI.RDNAttribute = RDNAttribute;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" RDN ">
    function RDN() {
        var obj;
        this.__proto__ = {
            set attributes(v) {
            },
            get attributes() {
                return obj;
            }
        };
        this.__proto__.toObject = function() {
            var obj = [];
            for (var i = 0; i < this.attributes.length; i++)
                obj.push(this.attributes[i].toObject());
            return obj;
        };
        this.__proto__.format = function(seporator, oids) {
            if (trusted.isObject(seporator) && oids === undefined) {
                oids = seporator;
                seporator = undefined;
            }
            if (seporator === undefined)
                seporator = ";";
            var str = "";
            for (var i = 0; i < obj.length; i++) {
                var attr = obj[i].format("+", oids);
                str += (i !== 0) ? seporator + attr : attr;
            }
            return str;
        };
        this.__proto__.toString = function() {
            return this.format();
        };

        this.__proto__.getAttributes = function(oid) {
            if (trusted.isString(oid))
                oid = new trusted.PKI.OID(oid);
            if (!(trusted.isObject(oid)))
                throw "Name.getAttribute: Параметр oid имеет неверное значение"
            var res = [];
            for (var i = 0; i < this.attributes.length; i++) {
                if (this.attributes[i].type.value === oid.value)
                    res.push(this.attributes[i]);
            }
            return res;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "RDN.new: parameter can not be undefined."
            v = objFromBuffer(v, "RelativeDistinguishedName");
            if (!trusted.isObject(v) && !trusted.isArray(v) ||
                    v.length === 0 ||
                    (v.length !== 0 &&
                            !(v[0].hasOwnProperty("type") || v[0].hasOwnProperty("value"))))
                throw "RDN.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.length; i++)
                obj.push(new trusted.PKI.RDNAttribute(v[i]));
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.RDN = RDN;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" Name ">
    function Name() {
        var obj;

        this.__proto__ = {
            set RDNs(v) {
            },
            get RDNs() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            var obj = [];
            for (var i = 0; i < this.RDNs.length; i++)
                obj.push(this.RDNs[i].toObject());
            return {rdnSequence: obj};
        };

        this.__proto__.format = function(seporator, oids) {
            if (trusted.isObject(seporator) && oids === undefined) {
                oids = seporator;
                seporator = undefined;
            }
            if (seporator === undefined)
                seporator = ";";
            var str = "";
            for (var i = 0; i < obj.length; i++) {
                var attr = obj[i].format("+", oids);
                str += (i !== 0) ? seporator + attr : attr;
            }
            return str;
        };
        this.__proto__.toString = function() {
            return this.format();
        };

        this.__proto__.getAttributes = function(oid) {
            var res = [];
            for (var i = 0; i < this.RDNs.length; i++) {
                res = res.concat(this.RDNs[i].getAttributes(oid));
            }
            return res;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "Name.new: parameter can not be undefined."
            v = objFromBuffer(v, "Name");
            if (!("rdnSequence" in v) && !trusted.isArray(v.rdnSequence) &&
                    v.length !== 0)
                throw "Name.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.rdnSequence.length; i++)
                obj.push(new trusted.PKI.RDN(v.rdnSequence[i]));
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.Name = Name;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" GeneralName ">

    function GeneralName() {
        var obj;
        var directoryName;
        var registeredID;

        this.__proto__ = {
            set name(v) {
            },
            get name() {
                switch (this.type) {
                    case trusted.PKI.GeneralNameType.OtherName:
                        return new trusted.PKI.OtherName(obj.otherName);
                    case trusted.PKI.GeneralNameType.RFC822Name:
                        return obj.rfc822Name;
                    case trusted.PKI.GeneralNameType.DNSName:
                        return obj.dNSName;
                    case trusted.PKI.GeneralNameType.DirectoryName:
                        //cache
                        if (directoryName === undefined)
                            directoryName = new trusted.PKI.Name(obj.directoryName);
                        return directoryName;
                    case trusted.PKI.GeneralNameType.UniformResourceIdentifier:
                        return obj.uniformResourceIdentifier;
                    case trusted.PKI.GeneralNameType.IPAddress:
                        var ip = obj.iPAddress;
                        ip.__proto__.toString = function() {
                            return Der.toHex(ip);
                        };
                        return ip;
                    case trusted.PKI.GeneralNameType.RegisteredID:
                        if (registeredID === undefined)
                            registeredID = new trusted.PKI.OID(obj.registeredID);
                        return registeredID;
                }
            },
            set type(v) {
            },
            get type() {
                var key = Object.keys(obj)[0];
                switch (key) {
                    case "otherName":
                        return trusted.PKI.GeneralNameType.OtherName;
                    case "rfc822Name":
                        return trusted.PKI.GeneralNameType.RFC822Name;
                    case "dNSName":
                        return trusted.PKI.GeneralNameType.DNSName;
                    case "x400Address":
                        return trusted.PKI.GeneralNameType.X400Address;
                    case "directoryName":
                        return trusted.PKI.GeneralNameType.DirectoryName;
                    case "ediPartyName":
                        return trusted.PKI.GeneralNameType.ediPartyName;
                    case "uniformResourceIdentifier":
                        return trusted.PKI.GeneralNameType.UniformResourceIdentifier;
                    case "iPAddress":
                        return trusted.PKI.GeneralNameType.IPAddress;
                    case "registeredID":
                        return trusted.PKI.GeneralNameType.RegisteredID;
                    default:
                        throw "GeneralName.type: Unknown type '" + key + "'";
                }
            }
        };

        this.__proto__.toObject = function() {
            switch (this.type) {
                case trusted.PKI.GeneralNameType.OtherName:
                    return {otherName: this.name.toObject()};
                case trusted.PKI.GeneralNameType.RFC822Name:
                    return {rfc822Name: this.name};
                case trusted.PKI.GeneralNameType.DNSName:
                    return {dNSName: this.name};
                case trusted.PKI.GeneralNameType.DirectoryName:
                    return {directoryName: this.name.toObject()};
                case trusted.PKI.GeneralNameType.UniformResourceIdentifier:
                    return {uniformResourceIdentifier: this.name};
                case trusted.PKI.GeneralNameType.IPAddress:
                    return {iPAddress: this.name};
                case trusted.PKI.GeneralNameType.RegisteredID:
                    return {registeredID: this.name.value};
            }
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "GeneralName.new: parameter can not be undefined."
            v = objFromBuffer(v, "GeneralName");
            if (!trusted.isObject(v) && !trusted.isArray(v) &&
                    v.length !== 0)
                throw "GeneralName.new: parameter is not valid."
            obj = v;
            this.type; // check for known types only
        }

        function createIsFunctions(v) {
            var keys = Object.keys(v);
            for (var i = 0; i < keys.length; i++) {
                var index = i; // Создаем копию i, иначе все функции будут использовать i = keys.
                this.__proto__["is" + keys[index]] = new Function("return this.type===" + v[keys[index]]);
            }
        }

        createIsFunctions.call(this, trusted.PKI.GeneralNameType);

        this.__proto__.toString = function() {
            switch (this.type) {
                case trusted.PKI.GeneralNameType.RFC822Name:
                case trusted.PKI.GeneralNameType.DNSName:
                case trusted.PKI.GeneralNameType.UniformResourceIdentifier:
                    return this.name;
                case trusted.PKI.GeneralNameType.OtherName:
                case trusted.PKI.GeneralNameType.DirectoryName:
                case trusted.PKI.GeneralNameType.RegisteredID:
                    return this.name.toString();
                case trusted.PKI.GeneralNameType.IPAddress:
                    return this.name.toString();
            }
        };

        init.call(this, arguments[0]);
    }

    trusted.PKI.GeneralName = GeneralName;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" GeneralNames ">
    function GeneralNames() {
        var obj;
        this.__proto__ = {
            set generalNames(v) {
            },
            get generalNames() {
                return obj;
            },
            set items(v) {
            },
            get items() {
                return this.generalNames();
            }
        };
        this.__proto__.toString = function() {
            var s = '';
            for (var i = 0; i < this.generalNames.length; i++)
                s += this.generalNames[i].toString() + ((i !== (this.generalNames.length - 1)) ? ";" : "");
            return s;
        };

        this.__proto__.toObject = function() {
            var obj = [];
            for (var i = 0; i < this.generalNames.length; i++)
                obj.push(this.generalNames[i].toObject());
            return obj;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "GeneralNames.new: parameter can not be undefined."
            v = objFromBuffer(v, "GeneralNames");
            if (!(trusted.isArray(v) && v.length !== 0))
                throw "GeneralNames.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.length; i++)
                obj.push(new trusted.PKI.GeneralName(v[i]));
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.GeneralNames = GeneralNames;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" OtherName ">
    function OtherName() {
        var obj, tid;

        this.__proto__ = {
            set typeID(v) {
            },
            get typeID() {
                if (tid === undefined)
                    tid = new trusted.PKI.OID(obj.typeId);
                return tid;
            },
            set OID(v) {
            },
            get OID() {
                return this.typeID;
            },
            set value(v) {
            },
            get value() {
                return obj.value;
            }
        };

        this.__proto__.toString = function() {
            return this.typeID.name + "=" + Der.toHex(this.value);
        };

        this.__proto__.toObject = function() {
            return {typeId: this.typeID.value, value: this.value};
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "OtherName.new: parameter can not be undefined."
            v = objFromBuffer(v, "OtherName");
            if (!(trusted.isObject(v) && ("typeId" in v) && ("value" in v)))
                throw "OtherName.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.OtherName = OtherName;
    // </editor-fold>

})();


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
})();(function(undefined) {
    function OID() {
        var _value;

        this.name = null;
        this.comment = null;

        this.__proto__ = {
            set value(v) {
                if (!checkValue(v))
                    throw "OID.setValue: Wrong value. (" + v + ")";
                if (v !== _value) {
                    _value = v;
                    var oid = trusted.oids[v];
                    if (oid !== undefined) {
                        this.name = oid.d;
                        this.comment = oid.c;
                    } else {
                        this.name = v;
                        this.comment = "";
                    }
                }
            },
            get value() {
                return _value;
            },
            get type(){
                return "OID";
            }
        };

        this.__proto__.toString = function() {
            var s = this.name;
            if (s !== this.value) {
                s += " (" + this.value + ")";
            }
            return s;
        };

        this.__proto__.toObject = function() {
            return this.value;
        };

        function checkValue(v) {
            if (typeof (v) !== "string")
                return false;
            var regex = /^[0-2](\.\d+)+$/g;
            return regex.test(v);
        }

        //constructor
        switch (arguments.length) {
            case 1:
                this.value = arguments[0];
        }

    }

    trusted.PKI.OID = OID;
})();// Converted from: https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
// which is made by Peter Gutmann and whose license states:
//   You can use this code in whatever way you want,
//   as long as you don't try to claim you wrote it.
if (!("trusted" in window))
    trusted = {};

trusted.oids = {
"0.2.262.1.10": { "d": "Telesec", "c": "Deutsche Telekom", "w": false },
"0.2.262.1.10.0": { "d": "extension", "c": "Telesec", "w": false },
"0.2.262.1.10.1": { "d": "mechanism", "c": "Telesec", "w": false },
"0.2.262.1.10.1.0": { "d": "authentication", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.0.1": { "d": "passwordAuthentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.2": { "d": "protectedPasswordAuthentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.3": { "d": "oneWayX509Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.4": { "d": "twoWayX509Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.5": { "d": "threeWayX509Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.6": { "d": "oneWayISO9798Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.7": { "d": "twoWayISO9798Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.8": { "d": "telekomAuthentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.1": { "d": "signature", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.1": { "d": "md4WithRSAAndISO9697", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.2": { "d": "md4WithRSAAndTelesecSignatureStandard", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.3": { "d": "md5WithRSAAndISO9697", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.4": { "d": "md5WithRSAAndTelesecSignatureStandard", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.5": { "d": "ripemd160WithRSAAndTelekomSignatureStandard", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.9": { "d": "hbciRsaSignature", "c": "Telesec signature", "w": false },
"0.2.262.1.10.1.2": { "d": "encryption", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.2.0": { "d": "none", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.1": { "d": "rsaTelesec", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2": { "d": "des", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.1": { "d": "desECB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.2": { "d": "desCBC", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.3": { "d": "desOFB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.4": { "d": "desCFB8", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.5": { "d": "desCFB64", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3": { "d": "des3", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.1": { "d": "des3ECB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.2": { "d": "des3CBC", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.3": { "d": "des3OFB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.4": { "d": "des3CFB8", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.5": { "d": "des3CFB64", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.4": { "d": "magenta", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5": { "d": "idea", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.1": { "d": "ideaECB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.2": { "d": "ideaCBC", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.3": { "d": "ideaOFB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.4": { "d": "ideaCFB8", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.5": { "d": "ideaCFB64", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.3": { "d": "oneWayFunction", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.3.1": { "d": "md4", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.2": { "d": "md5", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.3": { "d": "sqModNX509", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.4": { "d": "sqModNISO", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.5": { "d": "ripemd128", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.6": { "d": "hashUsingBlockCipher", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.7": { "d": "mac", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.8": { "d": "ripemd160", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.4": { "d": "fecFunction", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.4.1": { "d": "reedSolomon", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.2": { "d": "module", "c": "Telesec", "w": false },
"0.2.262.1.10.2.0": { "d": "algorithms", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.1": { "d": "attributeTypes", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.2": { "d": "certificateTypes", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.3": { "d": "messageTypes", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.4": { "d": "plProtocol", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.5": { "d": "smeAndComponentsOfSme", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.6": { "d": "fec", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.7": { "d": "usefulDefinitions", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.8": { "d": "stefiles", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.9": { "d": "sadmib", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.10": { "d": "electronicOrder", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.11": { "d": "telesecTtpAsymmetricApplication", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.12": { "d": "telesecTtpBasisApplication", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.13": { "d": "telesecTtpMessages", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.14": { "d": "telesecTtpTimeStampApplication", "c": "Telesec module", "w": false },
"0.2.262.1.10.3": { "d": "objectClass", "c": "Telesec", "w": false },
"0.2.262.1.10.3.0": { "d": "telesecOtherName", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.1": { "d": "directory", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.2": { "d": "directoryType", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.3": { "d": "directoryGroup", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.4": { "d": "directoryUser", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.5": { "d": "symmetricKeyEntry", "c": "Telesec object class", "w": false },
"0.2.262.1.10.4": { "d": "package", "c": "Telesec", "w": false },
"0.2.262.1.10.5": { "d": "parameter", "c": "Telesec", "w": false },
"0.2.262.1.10.6": { "d": "nameBinding", "c": "Telesec", "w": false },
"0.2.262.1.10.7": { "d": "attribute", "c": "Telesec", "w": false },
"0.2.262.1.10.7.0": { "d": "applicationGroupIdentifier", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.1": { "d": "certificateType", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.2": { "d": "telesecCertificate", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.3": { "d": "certificateNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.4": { "d": "certificateRevocationList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.5": { "d": "creationDate", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.6": { "d": "issuer", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.7": { "d": "namingAuthority", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.8": { "d": "publicKeyDirectory", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.9": { "d": "securityDomain", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.10": { "d": "subject", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.11": { "d": "timeOfRevocation", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.12": { "d": "userGroupReference", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.13": { "d": "validity", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.14": { "d": "zert93", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.15": { "d": "securityMessEnv", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.16": { "d": "anonymizedPublicKeyDirectory", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.17": { "d": "telesecGivenName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.18": { "d": "nameAdditions", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.19": { "d": "telesecPostalCode", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.20": { "d": "nameDistinguisher", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.21": { "d": "telesecCertificateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.22": { "d": "teletrustCertificateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.23": { "d": "x509CertificateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.24": { "d": "timeOfIssue", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.25": { "d": "physicalCardNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.26": { "d": "fileType", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.27": { "d": "ctlFileIsArchive", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.28": { "d": "emailAddress", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.29": { "d": "certificateTemplateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.30": { "d": "directoryName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.31": { "d": "directoryTypeName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.32": { "d": "directoryGroupName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.33": { "d": "directoryUserName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.34": { "d": "revocationFlag", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.35": { "d": "symmetricKeyEntryName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.36": { "d": "glNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.37": { "d": "goNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.38": { "d": "gKeyData", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.39": { "d": "zKeyData", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.40": { "d": "ktKeyData", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.41": { "d": "ktKeyNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.51": { "d": "timeOfRevocationGen", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.52": { "d": "liabilityText", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.8": { "d": "attributeGroup", "c": "Telesec", "w": false },
"0.2.262.1.10.9": { "d": "action", "c": "Telesec", "w": false },
"0.2.262.1.10.10": { "d": "notification", "c": "Telesec", "w": false },
"0.2.262.1.10.11": { "d": "snmp-mibs", "c": "Telesec", "w": false },
"0.2.262.1.10.11.1": { "d": "securityApplication", "c": "Telesec SNMP MIBs", "w": false },
"0.2.262.1.10.12": { "d": "certAndCrlExtensionDefinitions", "c": "Telesec", "w": false },
"0.2.262.1.10.12.0": { "d": "liabilityLimitationFlag", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.1": { "d": "telesecCertIdExt", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.2": { "d": "Telesec policyIdentifier", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.3": { "d": "telesecPolicyQualifierID", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.4": { "d": "telesecCRLFilteredExt", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.5": { "d": "telesecCRLFilterExt", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.6": { "d": "telesecNamingAuthorityExt", "c": "Telesec cert/CRL extension", "w": false },
"0.4.0.127.0.7": { "d": "bsi", "c": "BSI TR-03110/TR-03111", "w": false },
"0.4.0.127.0.7.1": { "d": "bsiEcc", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1": { "d": "bsifieldType", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.1": { "d": "bsiPrimeField", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2": { "d": "bsiCharacteristicTwoField", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3": { "d": "bsiCharacteristicTwoBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3.1": { "d": "bsiGnBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3.2": { "d": "bsiTpBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3.3": { "d": "bsiPpBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1": { "d": "bsiEcdsaSignatures", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.1": { "d": "bsiEcdsaWithSHA1", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.2": { "d": "bsiEcdsaWithSHA224", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.3": { "d": "bsiEcdsaWithSHA256", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.4": { "d": "bsiEcdsaWithSHA384", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.5": { "d": "bsiEcdsaWithSHA512", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.6": { "d": "bsiEcdsaWithRIPEMD160", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.2": { "d": "bsiEcKeyType", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.2.1": { "d": "bsiEcPublicKey", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.5.1": { "d": "bsiKaeg", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.5.1.1": { "d": "bsiKaegWithX963KDF", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.5.1.2": { "d": "bsiKaegWith3DESKDF", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.2.2.1": { "d": "bsiPK", "c": "BSI TR-03110. Formerly known as bsiCA, now moved to ...2.2.3.x", "w": false },
"0.4.0.127.0.7.2.2.1.1": { "d": "bsiPK_DH", "c": "BSI TR-03110. Formerly known as bsiCA_DH, now moved to ...2.2.3.x", "w": false },
"0.4.0.127.0.7.2.2.1.2": { "d": "bsiPK_ECDH", "c": "BSI TR-03110. Formerly known as bsiCA_ECDH, now moved to ...2.2.3.x", "w": false },
"0.4.0.127.0.7.2.2.2": { "d": "bsiTA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1": { "d": "bsiTA_RSA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.1": { "d": "bsiTA_RSAv1_5_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.2": { "d": "bsiTA_RSAv1_5_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.3": { "d": "bsiTA_RSAPSS_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.4": { "d": "bsiTA_RSAPSS_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.5": { "d": "bsiTA_RSAv1_5_SHA512", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.6": { "d": "bsiTA_RSAPSS_SHA512", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2": { "d": "bsiTA_ECDSA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.1": { "d": "bsiTA_ECDSA_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.2": { "d": "bsiTA_ECDSA_SHA224", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.3": { "d": "bsiTA_ECDSA_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.4": { "d": "bsiTA_ECDSA_SHA384", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.5": { "d": "bsiTA_ECDSA_SHA512", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3": { "d": "bsiCA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.1": { "d": "bsiCA_DH", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.1.1": { "d": "bsiCA_DH_3DES_CBC_CBC", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.1.2": { "d": "bsiCA_DH_AES_CBC_CMAC_128", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.1.3": { "d": "bsiCA_DH_AES_CBC_CMAC_192", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.1.4": { "d": "bsiCA_DH_AES_CBC_CMAC_256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.2": { "d": "bsiCA_ECDH", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.2.1": { "d": "bsiCA_ECDH_3DES_CBC_CBC", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.2.2": { "d": "bsiCA_ECDH_AES_CBC_CMAC_128", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.2.3": { "d": "bsiCA_ECDH_AES_CBC_CMAC_192", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.2.4": { "d": "bsiCA_ECDH_AES_CBC_CMAC_256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4": { "d": "bsiPACE", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.1": { "d": "bsiPACE_DH_GM", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.1.1": { "d": "bsiPACE_DH_GM_3DES_CBC_CBC", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.1.2": { "d": "bsiPACE_DH_GM_AES_CBC_CMAC_128", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.1.3": { "d": "bsiPACE_DH_GM_AES_CBC_CMAC_192", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.1.4": { "d": "bsiPACE_DH_GM_AES_CBC_CMAC_256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.2": { "d": "bsiPACE_ECDH_GM", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.2.1": { "d": "bsiPACE_ECDH_GM_3DES_CBC_CBC", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.2.2": { "d": "bsiPACE_ECDH_GM_AES_CBC_CMAC_128", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.2.3": { "d": "bsiPACE_ECDH_GM_AES_CBC_CMAC_192", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.2.4": { "d": "bsiPACE_ECDH_GM_AES_CBC_CMAC_256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.3": { "d": "bsiPACE_DH_IM", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.3.1": { "d": "bsiPACE_DH_IM_3DES_CBC_CBC", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.3.2": { "d": "bsiPACE_DH_IM_AES_CBC_CMAC_128", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.3.3": { "d": "bsiPACE_DH_IM_AES_CBC_CMAC_192", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.3.4": { "d": "bsiPACE_DH_IM_AES_CBC_CMAC_256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.4": { "d": "bsiPACE_ECDH_IM", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.4.1": { "d": "bsiPACE_ECDH_IM_3DES_CBC_CBC", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.4.2": { "d": "bsiPACE_ECDH_IM_AES_CBC_CMAC_128", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.4.3": { "d": "bsiPACE_ECDH_IM_AES_CBC_CMAC_192", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.4.4.4": { "d": "bsiPACE_ECDH_IM_AES_CBC_CMAC_256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5": { "d": "bsiRI", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.1": { "d": "bsiRI_DH", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.1.1": { "d": "bsiRI_DH_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.1.2": { "d": "bsiRI_DH_SHA224", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.1.3": { "d": "bsiRI_DH_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.1.4": { "d": "bsiRI_DH_SHA384", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.1.5": { "d": "bsiRI_DH_SHA512", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.2": { "d": "bsiRI_ECDH", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.2.1": { "d": "bsiRI_ECDH_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.2.2": { "d": "bsiRI_ECDH_SHA224", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.2.3": { "d": "bsiRI_ECDH_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.2.4": { "d": "bsiRI_ECDH_SHA384", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.5.2.5": { "d": "bsiRI_ECDH_SHA512", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.6": { "d": "bsiCardInfo", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.7": { "d": "bsiEidSecurity", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.8": { "d": "bsiPT", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.2": { "d": "bsiEACRoles", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.2.1": { "d": "bsiEACRolesIS", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.2.2": { "d": "bsiEACRolesAT", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.2.3": { "d": "bsiEACRolesST", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.3": { "d": "bsiTAv2ce", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.3.1": { "d": "bsiTAv2ceDescription", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.3.1.1": { "d": "bsiTAv2ceDescriptionPlainText", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.3.1.2": { "d": "bsiTAv2ceDescriptionIA5String", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.3.1.3": { "d": "bsiTAv2ceDescriptionOctetString", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.3.2": { "d": "bsiTAv2ceTerminalSector", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.4": { "d": "bsiAuxData", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.4.1": { "d": "bsiAuxDataBirthday", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.4.2": { "d": "bsiAuxDataExpireDate", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.4.3": { "d": "bsiAuxDataCommunityID", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.2.1": { "d": "bsiSecObj", "c": "BSI TR-03110", "w": false },
"0.4.0.1862": { "d": "etsiQcsProfile", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1": { "d": "etsiQcs", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.1": { "d": "etsiQcsCompliance", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.2": { "d": "etsiQcsLimitValue", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.3": { "d": "etsiQcsRetentionPeriod", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.4": { "d": "etsiQcsQcSSCD", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.9.2342.19200300.100.1.1": { "d": "userID", "c": "Some oddball X.500 attribute collection", "w": false },
"0.9.2342.19200300.100.1.3": { "d": "rfc822Mailbox", "c": "Some oddball X.500 attribute collection", "w": false },
"0.9.2342.19200300.100.1.25": { "d": "domainComponent", "c": "Men are from Mars, this OID is from Pluto", "w": false },
"1.0.10118.3.0.49": { "d": "ripemd160", "c": "ISO 10118-3 hash function", "w": false },
"1.0.10118.3.0.50": { "d": "ripemd128", "c": "ISO 10118-3 hash function", "w": false },
"1.0.10118.3.0.55": { "d": "whirlpool", "c": "ISO 10118-3 hash function", "w": false },
"1.2.36.1.3.1.1.1": { "d": "qgpki", "c": "Queensland Government PKI", "w": false },
"1.2.36.1.3.1.1.1.1": { "d": "qgpkiPolicies", "c": "QGPKI policies", "w": false },
"1.2.36.1.3.1.1.1.1.1": { "d": "qgpkiMedIntermedCA", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.1.1": { "d": "qgpkiMedIntermedIndividual", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.1.2": { "d": "qgpkiMedIntermedDeviceControl", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.1.3": { "d": "qgpkiMedIntermedDevice", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.1.4": { "d": "qgpkiMedIntermedAuthorisedParty", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.1.5": { "d": "qgpkiMedIntermedDeviceSystem", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2": { "d": "qgpkiMedIssuingCA", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.1": { "d": "qgpkiMedIssuingIndividual", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.2": { "d": "qgpkiMedIssuingDeviceControl", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.3": { "d": "qgpkiMedIssuingDevice", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.4": { "d": "qgpkiMedIssuingAuthorisedParty", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.5": { "d": "qgpkiMedIssuingClientAuth", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.6": { "d": "qgpkiMedIssuingServerAuth", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.7": { "d": "qgpkiMedIssuingDataProt", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.2.8": { "d": "qgpkiMedIssuingTokenAuth", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.3": { "d": "qgpkiBasicIntermedCA", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.3.1": { "d": "qgpkiBasicIntermedDeviceSystem", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.4": { "d": "qgpkiBasicIssuingCA", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.4.1": { "d": "qgpkiBasicIssuingClientAuth", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.4.2": { "d": "qgpkiBasicIssuingServerAuth", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.1.4.3": { "d": "qgpkiBasicIssuingDataSigning", "c": "QGPKI policy", "w": false },
"1.2.36.1.3.1.1.1.2": { "d": "qgpkiAssuranceLevel", "c": "QGPKI assurance level", "w": false },
"1.2.36.1.3.1.1.1.2.1": { "d": "qgpkiAssuranceRudimentary", "c": "QGPKI assurance level", "w": false },
"1.2.36.1.3.1.1.1.2.2": { "d": "qgpkiAssuranceBasic", "c": "QGPKI assurance level", "w": false },
"1.2.36.1.3.1.1.1.2.3": { "d": "qgpkiAssuranceMedium", "c": "QGPKI assurance level", "w": false },
"1.2.36.1.3.1.1.1.2.4": { "d": "qgpkiAssuranceHigh", "c": "QGPKI assurance level", "w": false },
"1.2.36.1.3.1.1.1.3": { "d": "qgpkiCertFunction", "c": "QGPKI policies", "w": false },
"1.2.36.1.3.1.1.1.3.1": { "d": "qgpkiFunctionIndividual", "c": "QGPKI policies", "w": false },
"1.2.36.1.3.1.1.1.3.2": { "d": "qgpkiFunctionDevice", "c": "QGPKI policies", "w": false },
"1.2.36.1.3.1.1.1.3.3": { "d": "qgpkiFunctionAuthorisedParty", "c": "QGPKI policies", "w": false },
"1.2.36.1.3.1.1.1.3.4": { "d": "qgpkiFunctionDeviceControl", "c": "QGPKI policies", "w": false },
"1.2.36.1.3.1.2": { "d": "qpspki", "c": "Queensland Police PKI", "w": false },
"1.2.36.1.3.1.2.1": { "d": "qpspkiPolicies", "c": "Queensland Police PKI", "w": false },
"1.2.36.1.3.1.2.1.2": { "d": "qpspkiPolicyBasic", "c": "Queensland Police PKI", "w": false },
"1.2.36.1.3.1.2.1.3": { "d": "qpspkiPolicyMedium", "c": "Queensland Police PKI", "w": false },
"1.2.36.1.3.1.2.1.4": { "d": "qpspkiPolicyHigh", "c": "Queensland Police PKI", "w": false },
"1.2.36.1.3.1.3.2": { "d": "qtmrpki", "c": "Queensland Transport PKI", "w": false },
"1.2.36.1.3.1.3.2.1": { "d": "qtmrpkiPolicies", "c": "Queensland Transport PKI", "w": false },
"1.2.36.1.3.1.3.2.2": { "d": "qtmrpkiPurpose", "c": "Queensland Transport PKI", "w": false },
"1.2.36.1.3.1.3.2.2.1": { "d": "qtmrpkiIndividual", "c": "Queensland Transport PKI purpose", "w": false },
"1.2.36.1.3.1.3.2.2.2": { "d": "qtmrpkiDeviceControl", "c": "Queensland Transport PKI purpose", "w": false },
"1.2.36.1.3.1.3.2.2.3": { "d": "qtmrpkiDevice", "c": "Queensland Transport PKI purpose", "w": false },
"1.2.36.1.3.1.3.2.2.4": { "d": "qtmrpkiAuthorisedParty", "c": "Queensland Transport PKI purpose", "w": false },
"1.2.36.1.3.1.3.2.2.5": { "d": "qtmrpkiDeviceSystem", "c": "Queensland Transport PKI purpose", "w": false },
"1.2.36.1.3.1.3.2.3": { "d": "qtmrpkiDevice", "c": "Queensland Transport PKI", "w": false },
"1.2.36.1.3.1.3.2.3.1": { "d": "qtmrpkiDriverLicense", "c": "Queensland Transport PKI device", "w": false },
"1.2.36.1.3.1.3.2.3.2": { "d": "qtmrpkiIndustryAuthority", "c": "Queensland Transport PKI device", "w": false },
"1.2.36.1.3.1.3.2.3.3": { "d": "qtmrpkiMarineLicense", "c": "Queensland Transport PKI device", "w": false },
"1.2.36.1.3.1.3.2.3.4": { "d": "qtmrpkiAdultProofOfAge", "c": "Queensland Transport PKI device", "w": false },
"1.2.36.1.3.1.3.2.3.5": { "d": "qtmrpkiSam", "c": "Queensland Transport PKI device", "w": false },
"1.2.36.1.3.1.3.2.4": { "d": "qtmrpkiAuthorisedParty", "c": "Queensland Transport PKI", "w": false },
"1.2.36.1.3.1.3.2.4.1": { "d": "qtmrpkiTransportInspector", "c": "Queensland Transport PKI authorised party", "w": false },
"1.2.36.1.3.1.3.2.4.2": { "d": "qtmrpkiPoliceOfficer", "c": "Queensland Transport PKI authorised party", "w": false },
"1.2.36.1.3.1.3.2.4.3": { "d": "qtmrpkiSystem", "c": "Queensland Transport PKI authorised party", "w": false },
"1.2.36.1.3.1.3.2.4.4": { "d": "qtmrpkiLiquorLicensingInspector", "c": "Queensland Transport PKI authorised party", "w": false },
"1.2.36.1.3.1.3.2.4.5": { "d": "qtmrpkiMarineEnforcementOfficer", "c": "Queensland Transport PKI authorised party", "w": false },
"1.2.36.1.333.1": { "d": "australianBusinessNumber", "c": "Australian Government corporate taxpayer ID", "w": false },
"1.2.36.68980861.1.1.2": { "d": "signetPersonal", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.3": { "d": "signetBusiness", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.4": { "d": "signetLegal", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.10": { "d": "signetPilot", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.11": { "d": "signetIntraNet", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.20": { "d": "signetPolicy", "c": "Signet CA", "w": false },
"1.2.36.75878867.1.100.1.1": { "d": "certificatesAustraliaPolicy", "c": "Certificates Australia CA", "w": false },
"1.2.392.200011.61.1.1.1": { "d": "mitsubishiSecurityAlgorithm", "c": "Mitsubishi security algorithm", "w": false },
"1.2.392.200011.61.1.1.1.1": { "d": "misty1-cbc", "c": "Mitsubishi security algorithm", "w": false },
"1.2.410.200004.1": { "d": "kisaAlgorithm", "c": "KISA algorithm", "w": false },
"1.2.410.200004.1.1": { "d": "kcdsa", "c": "Korean DSA", "w": false },
"1.2.410.200004.1.2": { "d": "has160", "c": "Korean hash algorithm", "w": false },
"1.2.410.200004.1.3": { "d": "seedECB", "c": "Korean SEED algorithm, ECB mode", "w": false },
"1.2.410.200004.1.4": { "d": "seedCBC", "c": "Korean SEED algorithm, CBC mode", "w": false },
"1.2.410.200004.1.5": { "d": "seedOFB", "c": "Korean SEED algorithm, OFB mode", "w": false },
"1.2.410.200004.1.6": { "d": "seedCFB", "c": "Korean SEED algorithm, CFB mode", "w": false },
"1.2.410.200004.1.7": { "d": "seedMAC", "c": "Korean SEED algorithm, MAC mode", "w": false },
"1.2.410.200004.1.8": { "d": "kcdsaWithHAS160", "c": "Korean signature algorithm", "w": false },
"1.2.410.200004.1.9": { "d": "kcdsaWithSHA1", "c": "Korean signature algorithm", "w": false },
"1.2.410.200004.1.10": { "d": "pbeWithHAS160AndSEED-ECB", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.11": { "d": "pbeWithHAS160AndSEED-CBC", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.12": { "d": "pbeWithHAS160AndSEED-CFB", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.13": { "d": "pbeWithHAS160AndSEED-OFB", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.14": { "d": "pbeWithSHA1AndSEED-ECB", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.15": { "d": "pbeWithSHA1AndSEED-CBC", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.16": { "d": "pbeWithSHA1AndSEED-CFB", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.17": { "d": "pbeWithSHA1AndSEED-OFB", "c": "Korean SEED algorithm, PBE key derivation", "w": false },
"1.2.410.200004.1.20": { "d": "rsaWithHAS160", "c": "Korean signature algorithm", "w": false },
"1.2.410.200004.1.21": { "d": "kcdsa1", "c": "Korean DSA", "w": false },
"1.2.410.200004.2": { "d": "npkiCP", "c": "KISA NPKI certificate policies", "w": false },
"1.2.410.200004.2.1": { "d": "npkiSignaturePolicy", "c": "KISA NPKI certificate policies", "w": false },
"1.2.410.200004.3": { "d": "npkiKP", "c": "KISA NPKI key usage", "w": false },
"1.2.410.200004.4": { "d": "npkiAT", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200004.5": { "d": "npkiLCA", "c": "KISA NPKI licensed CA", "w": false },
"1.2.410.200004.5.1": { "d": "npkiSignKorea", "c": "KISA NPKI licensed CA", "w": false },
"1.2.410.200004.5.2": { "d": "npkiSignGate", "c": "KISA NPKI licensed CA", "w": false },
"1.2.410.200004.5.3": { "d": "npkiNcaSign", "c": "KISA NPKI licensed CA", "w": false },
"1.2.410.200004.6": { "d": "npkiON", "c": "KISA NPKI otherName", "w": false },
"1.2.410.200004.7": { "d": "npkiAPP", "c": "KISA NPKI application", "w": false },
"1.2.410.200004.7.1": { "d": "npkiSMIME", "c": "KISA NPKI application", "w": false },
"1.2.410.200004.7.1.1": { "d": "npkiSMIMEAlgo", "c": "KISA NPKI application", "w": false },
"1.2.410.200004.7.1.1.1": { "d": "npkiCmsSEEDWrap", "c": "KISA NPKI application", "w": false },
"1.2.410.200004.10": { "d": "npki", "c": "KISA NPKI", "w": false },
"1.2.410.200004.10.1": { "d": "npkiAttribute", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200004.10.1.1": { "d": "npkiIdentifyData", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200004.10.1.1.1": { "d": "npkiVID", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200004.10.1.1.2": { "d": "npkiEncryptedVID", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200004.10.1.1.3": { "d": "npkiRandomNum", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200004.10.1.1.4": { "d": "npkiVID", "c": "KISA NPKI attribute", "w": false },
"1.2.410.200046.1.1": { "d": "aria1AlgorithmModes", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.1": { "d": "aria128-ecb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.2": { "d": "aria128-cbc", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.3": { "d": "aria128-cfb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.4": { "d": "aria128-ofb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.5": { "d": "aria128-ctr", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.6": { "d": "aria192-ecb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.7": { "d": "aria192-cbc", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.8": { "d": "aria192-cfb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.9": { "d": "aria192-ofb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.10": { "d": "aria192-ctr", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.11": { "d": "aria256-ecb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.12": { "d": "aria256-cbc", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.13": { "d": "aria256-cfb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.14": { "d": "aria256-ofb", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.15": { "d": "aria256-ctr", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.21": { "d": "aria128-cmac", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.22": { "d": "aria192-cmac", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.23": { "d": "aria256-cmac", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.31": { "d": "aria128-ocb2", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.32": { "d": "aria192-ocb2", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.33": { "d": "aria256-ocb2", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.34": { "d": "aria128-gcm", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.35": { "d": "aria192-gcm", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.36": { "d": "aria256-gcm", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.37": { "d": "aria128-ccm", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.38": { "d": "aria192-ccm", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.39": { "d": "aria256-ccm", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.40": { "d": "aria128-keywrap", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.41": { "d": "aria192-keywrap", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.42": { "d": "aria256-keywrap", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.43": { "d": "aria128-keywrapWithPad", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.44": { "d": "aria192-keywrapWithPad", "c": "ARIA algorithm modes", "w": false },
"1.2.410.200046.1.1.45": { "d": "aria256-keywrapWithPad", "c": "ARIA algorithm modes", "w": false },
"1.2.643.2.2.3": { "d": "gostSignature", "c": "GOST R 34.10-2001 + GOST R 34.11-94 signature", "w": false },
"1.2.643.2.2.4": { "d": "gost94Signature", "c": "GOST R 34.10-94 + GOST R 34.11-94 signature. Obsoleted by GOST R 34.10-2001", "w": true },
"1.2.643.2.2.19": { "d": "gostPublicKey", "c": "GOST R 34.10-2001 (ECC) public key", "w": false },
"1.2.643.2.2.20": { "d": "gost94PublicKey", "c": "GOST R 34.10-94 public key. Obsoleted by GOST R 34.10-2001", "w": true },
"1.2.643.2.2.21": { "d": "gostCipher", "c": "GOST 28147-89 (symmetric key block cipher)", "w": false },
"1.2.643.2.2.31.0": { "d": "testCipherParams", "c": "Test params for GOST 28147-89", "w": false },
"1.2.643.2.2.31.1": { "d": "cryptoProCipherA", "c": "CryptoPro params A for GOST 28147-89", "w": false },
"1.2.643.2.2.31.2": { "d": "cryptoProCipherB", "c": "CryptoPro params B for GOST 28147-89", "w": false },
"1.2.643.2.2.31.3": { "d": "cryptoProCipherC", "c": "CryptoPro params C for GOST 28147-89", "w": false },
"1.2.643.2.2.31.4": { "d": "cryptoProCipherD", "c": "CryptoPro params D for GOST 28147-89", "w": false },
"1.2.643.2.2.31.5": { "d": "oscar11Cipher", "c": "Oscar-1.1 params for GOST 28147-89", "w": false },
"1.2.643.2.2.31.6": { "d": "oscar10Cipher", "c": "Oscar-1.0 params for GOST 28147-89", "w": false },
"1.2.643.2.2.31.7": { "d": "ric1Cipher", "c": "RIC-1 params for GOST 28147-89", "w": false },
"1.2.643.2.2.9": { "d": "gostDigest", "c": "GOST R 34.11-94 digest", "w": false },
"1.2.643.2.2.30.0": { "d": "testDigestParams", "c": "Test params for GOST R 34.11-94", "w": false },
"1.2.643.2.2.30.1": { "d": "cryptoProDigestA", "c": "CryptoPro digest params for GOST R 34.11-94", "w": false },
"1.2.643.2.2.35.0": { "d": "testSignParams", "c": "Test elliptic curve for GOST R 34.11-2001", "w": false },
"1.2.643.2.2.35.1": { "d": "cryptoProSignA", "c": "CryptoPro ell.curve A for GOST R 34.11-2001", "w": false },
"1.2.643.2.2.35.2": { "d": "cryptoProSignB", "c": "CryptoPro ell.curve B for GOST R 34.11-2001", "w": false },
"1.2.643.2.2.35.3": { "d": "cryptoProSignC", "c": "CryptoPro ell.curve C for GOST R 34.11-2001", "w": false },
"1.2.643.2.2.36.0": { "d": "cryptoProSignXA", "c": "CryptoPro ell.curve XA for GOST R 34.11-2001", "w": false },
"1.2.643.2.2.36.1": { "d": "cryptoProSignXB", "c": "CryptoPro ell.curve XB for GOST R 34.11-2001", "w": false },
"1.2.643.2.2.14.0": { "d": "nullMeshing", "c": "Do not mesh state of GOST 28147-89 cipher", "w": false },
"1.2.643.2.2.14.1": { "d": "cryptoProMeshing", "c": "CryptoPro meshing of state of GOST 28147-89 cipher", "w": false },
"1.2.643.2.2.10": { "d": "hmacGost", "c": "HMAC with GOST R 34.11-94", "w": false },
"1.2.643.2.2.13.0": { "d": "gostWrap", "c": "Wrap key using GOST 28147-89 key", "w": false },
"1.2.643.2.2.13.1": { "d": "cryptoProWrap", "c": "Wrap key using diversified GOST 28147-89 key", "w": false },
"1.2.643.2.2.96": { "d": "cryptoProECDHWrap", "c": "Wrap key using ECC DH on GOST R 34.10-2001 keys (VKO)", "w": false },
"1.2.752.34.1": { "d": "seis-cp", "c": "SEIS Project", "w": false },
"1.2.752.34.1.1": { "d": "SEIS high-assurance policyIdentifier", "c": "SEIS Project certificate policies", "w": false },
"1.2.752.34.1.2": { "d": "SEIS GAK policyIdentifier", "c": "SEIS Project certificate policies", "w": false },
"1.2.752.34.2": { "d": "SEIS pe", "c": "SEIS Project", "w": false },
"1.2.752.34.3": { "d": "SEIS at", "c": "SEIS Project", "w": false },
"1.2.752.34.3.1": { "d": "SEIS at-personalIdentifier", "c": "SEIS Project attribute", "w": false },
"1.2.840.10040.1": { "d": "module", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.1.1": { "d": "x9f1-cert-mgmt", "c": "ANSI X9.57 module", "w": false },
"1.2.840.10040.2": { "d": "holdinstruction", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.2.1": { "d": "holdinstruction-none", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.2.2": { "d": "callissuer", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.2.3": { "d": "reject", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.2.4": { "d": "pickupToken", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.3": { "d": "attribute", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.3.1": { "d": "countersignature", "c": "ANSI X9.57 attribute", "w": false },
"1.2.840.10040.3.2": { "d": "attribute-cert", "c": "ANSI X9.57 attribute", "w": false },
"1.2.840.10040.4": { "d": "algorithm", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.4.1": { "d": "dsa", "c": "ANSI X9.57 algorithm", "w": false },
"1.2.840.10040.4.2": { "d": "dsa-match", "c": "ANSI X9.57 algorithm", "w": false },
"1.2.840.10040.4.3": { "d": "dsaWithSha1", "c": "ANSI X9.57 algorithm", "w": false },
"1.2.840.10045.1": { "d": "fieldType", "c": "ANSI X9.62. This OID is also assigned as ecdsa-with-SHA1", "w": false },
"1.2.840.10045.1.1": { "d": "prime-field", "c": "ANSI X9.62 field type", "w": false },
"1.2.840.10045.1.2": { "d": "characteristic-two-field", "c": "ANSI X9.62 field type", "w": false },
"1.2.840.10045.1.2.3": { "d": "characteristic-two-basis", "c": "ANSI X9.62 field type", "w": false },
"1.2.840.10045.1.2.3.1": { "d": "onBasis", "c": "ANSI X9.62 field basis", "w": false },
"1.2.840.10045.1.2.3.2": { "d": "tpBasis", "c": "ANSI X9.62 field basis", "w": false },
"1.2.840.10045.1.2.3.3": { "d": "ppBasis", "c": "ANSI X9.62 field basis", "w": false },
"1.2.840.10045.2": { "d": "publicKeyType", "c": "ANSI X9.62", "w": false },
"1.2.840.10045.2.1": { "d": "ecPublicKey", "c": "ANSI X9.62 public key type", "w": false },
"1.2.840.10045.3.0.1": { "d": "c2pnb163v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.2": { "d": "c2pnb163v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.3": { "d": "c2pnb163v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.5": { "d": "c2tnb191v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.6": { "d": "c2tnb191v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.7": { "d": "c2tnb191v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.10": { "d": "c2pnb208w1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.11": { "d": "c2tnb239v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.12": { "d": "c2tnb239v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.13": { "d": "c2tnb239v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.16": { "d": "c2pnb272w1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.18": { "d": "c2tnb359v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.19": { "d": "c2pnb368w1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.20": { "d": "c2tnb431r1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1": { "d": "prime192v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.2": { "d": "prime192v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.3": { "d": "prime192v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.4": { "d": "prime239v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.5": { "d": "prime239v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.6": { "d": "prime239v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.7": { "d": "prime256v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.4.1": { "d": "ecdsaWithSHA1", "c": "ANSI X9.62 ECDSA algorithm with SHA1", "w": false },
"1.2.840.10045.4.2": { "d": "ecdsaWithRecommended", "c": "ANSI X9.62 ECDSA algorithm with Recommended", "w": false },
"1.2.840.10045.4.3": { "d": "ecdsaWithSpecified", "c": "ANSI X9.62 ECDSA algorithm with Specified", "w": false },
"1.2.840.10045.4.3.1": { "d": "ecdsaWithSHA224", "c": "ANSI X9.62 ECDSA algorithm with SHA224", "w": false },
"1.2.840.10045.4.3.2": { "d": "ecdsaWithSHA256", "c": "ANSI X9.62 ECDSA algorithm with SHA256", "w": false },
"1.2.840.10045.4.3.3": { "d": "ecdsaWithSHA384", "c": "ANSI X9.62 ECDSA algorithm with SHA384", "w": false },
"1.2.840.10045.4.3.4": { "d": "ecdsaWithSHA512", "c": "ANSI X9.62 ECDSA algorithm with SHA512", "w": false },
"1.2.840.10046.1": { "d": "fieldType", "c": "ANSI X9.42", "w": false },
"1.2.840.10046.1.1": { "d": "gf-prime", "c": "ANSI X9.42 field type", "w": false },
"1.2.840.10046.2": { "d": "numberType", "c": "ANSI X9.42", "w": false },
"1.2.840.10046.2.1": { "d": "dhPublicKey", "c": "ANSI X9.42 number type", "w": false },
"1.2.840.10046.3": { "d": "scheme", "c": "ANSI X9.42", "w": false },
"1.2.840.10046.3.1": { "d": "dhStatic", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.2": { "d": "dhEphem", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.3": { "d": "dhHybrid1", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.4": { "d": "dhHybrid2", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.5": { "d": "mqv2", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.6": { "d": "mqv1", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10065.2.2": { "d": "?", "c": "ASTM 31.20", "w": false },
"1.2.840.10065.2.3": { "d": "healthcareLicense", "c": "ASTM 31.20", "w": false },
"1.2.840.10065.2.3.1.1": { "d": "license?", "c": "ASTM 31.20 healthcare license type", "w": false },
"1.2.840.113533.7": { "d": "nsn", "c": "", "w": false },
"1.2.840.113533.7.65": { "d": "nsn-ce", "c": "", "w": false },
"1.2.840.113533.7.65.0": { "d": "entrustVersInfo", "c": "Nortel Secure Networks ce", "w": false },
"1.2.840.113533.7.66": { "d": "nsn-alg", "c": "", "w": false },
"1.2.840.113533.7.66.3": { "d": "cast3CBC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.10": { "d": "cast5CBC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.11": { "d": "cast5MAC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.12": { "d": "pbeWithMD5AndCAST5-CBC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.13": { "d": "passwordBasedMac", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.67": { "d": "nsn-oc", "c": "", "w": false },
"1.2.840.113533.7.67.0": { "d": "entrustUser", "c": "Nortel Secure Networks oc", "w": false },
"1.2.840.113533.7.68": { "d": "nsn-at", "c": "", "w": false },
"1.2.840.113533.7.68.0": { "d": "entrustCAInfo", "c": "Nortel Secure Networks at", "w": false },
"1.2.840.113533.7.68.10": { "d": "attributeCertificate", "c": "Nortel Secure Networks at", "w": false },
"1.2.840.113549.1.1": { "d": "pkcs-1", "c": "", "w": false },
"1.2.840.113549.1.1.1": { "d": "rsaEncryption", "c": "PKCS #1", "w": false }, 
"1.2.840.113549.1.1.2": { "d": "md2WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.3": { "d": "md4WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.4": { "d": "md5WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.5": { "d": "sha1WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.7": { "d": "rsaOAEP", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.8": { "d": "pkcs1-MGF", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.9": { "d": "rsaOAEP-pSpecified", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.10": { "d": "rsaPSS", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.11": { "d": "sha256WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.12": { "d": "sha384WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.13": { "d": "sha512WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.14": { "d": "sha224WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.6": { "d": "rsaOAEPEncryptionSET", "c": "PKCS #1. This OID may also be assigned as ripemd160WithRSAEncryption", "w": false },
"1.2.840.113549.1.2": { "d": "bsafeRsaEncr", "c": "Obsolete BSAFE OID", "w": true },
"1.2.840.113549.1.3": { "d": "pkcs-3", "c": "", "w": false },
"1.2.840.113549.1.3.1": { "d": "dhKeyAgreement", "c": "PKCS #3", "w": false },
"1.2.840.113549.1.5": { "d": "pkcs-5", "c": "", "w": false },
"1.2.840.113549.1.5.1": { "d": "pbeWithMD2AndDES-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.3": { "d": "pbeWithMD5AndDES-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.4": { "d": "pbeWithMD2AndRC2-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.6": { "d": "pbeWithMD5AndRC2-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.9": { "d": "pbeWithMD5AndXOR", "c": "PKCS #5, used in BSAFE only", "w": true },
"1.2.840.113549.1.5.10": { "d": "pbeWithSHAAndDES-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.12": { "d": "pkcs5PBKDF2", "c": "PKCS #5 v2.0", "w": false },
"1.2.840.113549.1.5.13": { "d": "pkcs5PBES2", "c": "PKCS #5 v2.0", "w": false },
"1.2.840.113549.1.5.14": { "d": "pkcs5PBMAC1", "c": "PKCS #5 v2.0", "w": false },
"1.2.840.113549.1.7": { "d": "pkcs-7", "c": "", "w": false },
"1.2.840.113549.1.7.1": { "d": "data", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.2": { "d": "signedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.3": { "d": "envelopedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.4": { "d": "signedAndEnvelopedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.5": { "d": "digestedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.6": { "d": "encryptedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.7": { "d": "dataWithAttributes", "c": "PKCS #7 experimental", "w": true },
"1.2.840.113549.1.7.8": { "d": "encryptedPrivateKeyInfo", "c": "PKCS #7 experimental", "w": true },
"1.2.840.113549.1.9": { "d": "pkcs-9", "c": "", "w": false },
"1.2.840.113549.1.9.1": { "d": "emailAddress", "c": "PKCS #9. Deprecated, use an altName extension instead", "w": false },
"1.2.840.113549.1.9.2": { "d": "unstructuredName", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.3": { "d": "contentType", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.4": { "d": "messageDigest", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.5": { "d": "signingTime", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.6": { "d": "countersignature", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.7": { "d": "challengePassword", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.8": { "d": "unstructuredAddress", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.9": { "d": "extendedCertificateAttributes", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.10": { "d": "issuerAndSerialNumber", "c": "PKCS #9 experimental", "w": true },
"1.2.840.113549.1.9.11": { "d": "passwordCheck", "c": "PKCS #9 experimental", "w": true },
"1.2.840.113549.1.9.12": { "d": "publicKey", "c": "PKCS #9 experimental", "w": true },
"1.2.840.113549.1.9.13": { "d": "signingDescription", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.14": { "d": "extensionRequest", "c": "PKCS #9 via CRMF", "w": false },
"1.2.840.113549.1.9.15": { "d": "sMIMECapabilities", "c": "PKCS #9. This OID was formerly assigned as symmetricCapabilities, then reassigned as SMIMECapabilities, then renamed to the current name", "w": false },
"1.2.840.113549.1.9.15.1": { "d": "preferSignedData", "c": "sMIMECapabilities", "w": false },
"1.2.840.113549.1.9.15.2": { "d": "canNotDecryptAny", "c": "sMIMECapabilities", "w": false },
"1.2.840.113549.1.9.15.3": { "d": "receiptRequest", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 2 1) instead", "w": true },
"1.2.840.113549.1.9.15.4": { "d": "receipt", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 1 1) instead", "w": true },
"1.2.840.113549.1.9.15.5": { "d": "contentHints", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 2 4) instead", "w": true },
"1.2.840.113549.1.9.15.6": { "d": "mlExpansionHistory", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 2 3) instead", "w": true },
"1.2.840.113549.1.9.16": { "d": "id-sMIME", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.16.0": { "d": "id-mod", "c": "id-sMIME", "w": false },
"1.2.840.113549.1.9.16.0.1": { "d": "id-mod-cms", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.2": { "d": "id-mod-ess", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.3": { "d": "id-mod-oid", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.4": { "d": "id-mod-msg-v3", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.5": { "d": "id-mod-ets-eSignature-88", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.6": { "d": "id-mod-ets-eSignature-97", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.7": { "d": "id-mod-ets-eSigPolicy-88", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.8": { "d": "id-mod-ets-eSigPolicy-88", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.1": { "d": "contentType", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.1.1": { "d": "receipt", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.2": { "d": "authData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.3": { "d": "publishCert", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.4": { "d": "tSTInfo", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.5": { "d": "tDTInfo", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.6": { "d": "contentInfo", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.7": { "d": "dVCSRequestData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.8": { "d": "dVCSResponseData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.9": { "d": "compressedData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.10": { "d": "scvpCertValRequest", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.11": { "d": "scvpCertValResponse", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.12": { "d": "scvpValPolRequest", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.13": { "d": "scvpValPolResponse", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.14": { "d": "attrCertEncAttrs", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.15": { "d": "tSReq", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.16": { "d": "firmwarePackage", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.17": { "d": "firmwareLoadReceipt", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.18": { "d": "firmwareLoadError", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.19": { "d": "contentCollection", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.20": { "d": "contentWithAttrs", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.21": { "d": "encKeyWithID", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.22": { "d": "encPEPSI", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.23": { "d": "authEnvelopedData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.24": { "d": "routeOriginAttest", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.25": { "d": "symmetricKeyPackage", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.26": { "d": "rpkiManifest", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.27": { "d": "asciiTextWithCRLF", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.28": { "d": "xml", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.29": { "d": "pdf", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.30": { "d": "postscript", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.31": { "d": "timestampedData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.32": { "d": "asAdjacencyAttest", "c": "S/MIME Content Types", "w": true },
"1.2.840.113549.1.9.16.1.33": { "d": "rpkiTrustAnchor", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.34": { "d": "trustAnchorList", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.2": { "d": "authenticatedAttributes", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.2.1": { "d": "receiptRequest", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.2": { "d": "securityLabel", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.3": { "d": "mlExpandHistory", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.4": { "d": "contentHint", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.5": { "d": "msgSigDigest", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.6": { "d": "encapContentType", "c": "S/MIME Authenticated Attributes.  Obsolete", "w": true },
"1.2.840.113549.1.9.16.2.7": { "d": "contentIdentifier", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.8": { "d": "macValue", "c": "S/MIME Authenticated Attributes.  Obsolete", "w": true },
"1.2.840.113549.1.9.16.2.9": { "d": "equivalentLabels", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.10": { "d": "contentReference", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.11": { "d": "encrypKeyPref", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.12": { "d": "signingCertificate", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.13": { "d": "smimeEncryptCerts", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.14": { "d": "timeStampToken", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.15": { "d": "sigPolicyId", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.16": { "d": "commitmentType", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.17": { "d": "signerLocation", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.18": { "d": "signerAttr", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.19": { "d": "otherSigCert", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.20": { "d": "contentTimestamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.21": { "d": "certificateRefs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.22": { "d": "revocationRefs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.23": { "d": "certValues", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.24": { "d": "revocationValues", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.25": { "d": "escTimeStamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.26": { "d": "certCRLTimestamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.27": { "d": "archiveTimeStamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.28": { "d": "signatureType", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.29": { "d": "dvcsDvc", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.30": { "d": "cekReference", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.31": { "d": "maxCEKDecrypts", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.32": { "d": "kekDerivationAlg", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.33": { "d": "intendedRecipients", "c": "S/MIME Authenticated Attributes.  Obsolete", "w": true },
"1.2.840.113549.1.9.16.2.34": { "d": "cmcUnsignedData", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.35": { "d": "fwPackageID", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.36": { "d": "fwTargetHardwareIDs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.37": { "d": "fwDecryptKeyID", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.38": { "d": "fwImplCryptAlgs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.39": { "d": "fwWrappedFirmwareKey", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.40": { "d": "fwCommunityIdentifiers", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.41": { "d": "fwPkgMessageDigest", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.42": { "d": "fwPackageInfo", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.43": { "d": "fwImplCompressAlgs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.44": { "d": "etsAttrCertificateRefs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.45": { "d": "etsAttrRevocationRefs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.46": { "d": "binarySigningTime", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.47": { "d": "signingCertificateV2", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.48": { "d": "etsArchiveTimeStampV2", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.49": { "d": "erInternal", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.50": { "d": "erExternal", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.51": { "d": "multipleSignatures", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.3.1": { "d": "esDHwith3DES", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.2": { "d": "esDHwithRC2", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.3": { "d": "3desWrap", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.4": { "d": "rc2Wrap", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.5": { "d": "esDH", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.6": { "d": "cms3DESwrap", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.7": { "d": "cmsRC2wrap", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.8": { "d": "zlib", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.9": { "d": "pwriKEK", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.10": { "d": "ssDH", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.11": { "d": "hmacWith3DESwrap", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.12": { "d": "hmacWithAESwrap", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.13": { "d": "md5XorExperiment", "c": "S/MIME Algorithms.  Experimental", "w": true },
"1.2.840.113549.1.9.16.3.14": { "d": "rsaKEM", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.15": { "d": "authEnc128", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.16": { "d": "authEnc256", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.4.1": { "d": "certDist-ldap", "c": "S/MIME Certificate Distribution", "w": false },
"1.2.840.113549.1.9.16.5.1": { "d": "sigPolicyQualifier-spuri x", "c": "S/MIME Signature Policy Qualifiers", "w": false },
"1.2.840.113549.1.9.16.5.2": { "d": "sigPolicyQualifier-spUserNotice", "c": "S/MIME Signature Policy Qualifiers", "w": false },
"1.2.840.113549.1.9.16.6.1": { "d": "proofOfOrigin", "c": "S/MIME Commitment Type Identifiers", "w": false },
"1.2.840.113549.1.9.16.6.2": { "d": "proofOfReceipt", "c": "S/MIME Commitment Type Identifiers", "w": false },
"1.2.840.113549.1.9.16.6.3": { "d": "proofOfDelivery", "c": "S/MIME Commitment Type Identifiers", "w": false },
"1.2.840.113549.1.9.16.6.4": { "d": "proofOfSender", "c": "S/MIME Commitment Type Identifiers", "w": false },
"1.2.840.113549.1.9.16.6.5": { "d": "proofOfApproval", "c": "S/MIME Commitment Type Identifiers", "w": false },
"1.2.840.113549.1.9.16.6.6": { "d": "proofOfCreation", "c": "S/MIME Commitment Type Identifiers", "w": false },
"1.2.840.113549.1.9.16.8.1": { "d": "glUseKEK", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.2": { "d": "glDelete", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.3": { "d": "glAddMember", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.4": { "d": "glDeleteMember", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.5": { "d": "glRekey", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.6": { "d": "glAddOwner", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.7": { "d": "glRemoveOwner", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.8": { "d": "glkCompromise", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.9": { "d": "glkRefresh", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.10": { "d": "glFailInfo", "c": "S/MIME Symmetric Key Distribution Attributes.  Obsolete", "w": true },
"1.2.840.113549.1.9.16.8.11": { "d": "glaQueryRequest", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.12": { "d": "glaQueryResponse", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.13": { "d": "glProvideCert", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.14": { "d": "glUpdateCert", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.8.15": { "d": "glKey", "c": "S/MIME Symmetric Key Distribution Attributes", "w": false },
"1.2.840.113549.1.9.16.9": { "d": "signatureTypeIdentifier", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.9.1": { "d": "originatorSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.9.2": { "d": "domainSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.9.3": { "d": "additionalAttributesSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.9.4": { "d": "reviewSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.11": { "d": "capabilities", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.11.1": { "d": "preferBinaryInside", "c": "S/MIME Capability", "w": false },
"1.2.840.113549.1.9.20": { "d": "friendlyName (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.21": { "d": "localKeyID (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.22": { "d": "certTypes (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.22.1": { "d": "x509Certificate (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.22.2": { "d": "sdsiCertificate (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.23": { "d": "crlTypes (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.23.1": { "d": "x509Crl (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.24": { "d": "pkcs9objectClass", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.9.25": { "d": "pkcs9attributes", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.9.25.1": { "d": "pkcs15Token", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.2": { "d": "encryptedPrivateKeyInfo", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.3": { "d": "randomNonce", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.4": { "d": "sequenceNumber", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.5": { "d": "pkcs7PDU", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.26": { "d": "pkcs9syntax", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.9.27": { "d": "pkcs9matchingRules", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.12": { "d": "pkcs-12", "c": "", "w": false },
"1.2.840.113549.1.12.1": { "d": "pkcs-12-PbeIds", "c": "This OID was formerly assigned as PKCS #12 modeID", "w": false },
"1.2.840.113549.1.12.1.1": { "d": "pbeWithSHAAnd128BitRC4", "c": "PKCS #12 PbeIds. This OID was formerly assigned as pkcs-12-OfflineTransportMode", "w": false },
"1.2.840.113549.1.12.1.2": { "d": "pbeWithSHAAnd40BitRC4", "c": "PKCS #12 PbeIds. This OID was formerly assigned as pkcs-12-OnlineTransportMode", "w": false },
"1.2.840.113549.1.12.1.3": { "d": "pbeWithSHAAnd3-KeyTripleDES-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.1.4": { "d": "pbeWithSHAAnd2-KeyTripleDES-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.1.5": { "d": "pbeWithSHAAnd128BitRC2-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.1.6": { "d": "pbeWithSHAAnd40BitRC2-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.2": { "d": "pkcs-12-ESPVKID", "c": "Deprecated", "w": true },
"1.2.840.113549.1.12.2.1": { "d": "pkcs-12-PKCS8KeyShrouding", "c": "PKCS #12 ESPVKID. Deprecated, use (1 2 840 113549 1 12 3 5) instead", "w": true },
"1.2.840.113549.1.12.3": { "d": "pkcs-12-BagIds", "c": "", "w": false },
"1.2.840.113549.1.12.3.1": { "d": "pkcs-12-keyBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.2": { "d": "pkcs-12-certAndCRLBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.3": { "d": "pkcs-12-secretBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.4": { "d": "pkcs-12-safeContentsId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.5": { "d": "pkcs-12-pkcs-8ShroudedKeyBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.4": { "d": "pkcs-12-CertBagID", "c": "Deprecated", "w": true },
"1.2.840.113549.1.12.4.1": { "d": "pkcs-12-X509CertCRLBagID", "c": "PKCS #12 CertBagID. This OID was formerly assigned as pkcs-12-X509CertCRLBag", "w": false },
"1.2.840.113549.1.12.4.2": { "d": "pkcs-12-SDSICertBagID", "c": "PKCS #12 CertBagID. This OID was formerly assigned as pkcs-12-SDSICertBag", "w": false },
"1.2.840.113549.1.12.5": { "d": "pkcs-12-OID", "c": "", "w": true },
"1.2.840.113549.1.12.5.1": { "d": "pkcs-12-PBEID", "c": "PKCS #12 OID. Deprecated, use the partially compatible (1 2 840 113549 1 12 1) OIDs instead", "w": true },
"1.2.840.113549.1.12.5.1.1": { "d": "pkcs-12-PBEWithSha1And128BitRC4", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 1) instead", "w": true },
"1.2.840.113549.1.12.5.1.2": { "d": "pkcs-12-PBEWithSha1And40BitRC4", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 2) instead", "w": true },
"1.2.840.113549.1.12.5.1.3": { "d": "pkcs-12-PBEWithSha1AndTripleDESCBC", "c": "PKCS #12 OID PBEID. Deprecated, use the incompatible but similar (1 2 840 113549 1 12 1 3) or (1 2 840 113549 1 12 1 4) instead", "w": true },
"1.2.840.113549.1.12.5.1.4": { "d": "pkcs-12-PBEWithSha1And128BitRC2CBC", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 5) instead", "w": true },
"1.2.840.113549.1.12.5.1.5": { "d": "pkcs-12-PBEWithSha1And40BitRC2CBC", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 6) instead", "w": true },
"1.2.840.113549.1.12.5.1.6": { "d": "pkcs-12-PBEWithSha1AndRC4", "c": "PKCS #12 OID PBEID. Deprecated, use the incompatible but similar (1 2 840 113549 1 12 1 1) or (1 2 840 113549 1 12 1 2) instead", "w": true },
"1.2.840.113549.1.12.5.1.7": { "d": "pkcs-12-PBEWithSha1AndRC2CBC", "c": "PKCS #12 OID PBEID. Deprecated, use the incompatible but similar (1 2 840 113549 1 12 1 5) or (1 2 840 113549 1 12 1 6) instead", "w": true },
"1.2.840.113549.1.12.5.2": { "d": "pkcs-12-EnvelopingID", "c": "PKCS #12 OID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": false },
"1.2.840.113549.1.12.5.2.1": { "d": "pkcs-12-RSAEncryptionWith128BitRC4", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.2.2": { "d": "pkcs-12-RSAEncryptionWith40BitRC4", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.2.3": { "d": "pkcs-12-RSAEncryptionWithTripleDES", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.3": { "d": "pkcs-12-SignatureID", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.3.1": { "d": "pkcs-12-RSASignatureWithSHA1Digest", "c": "PKCS #12 OID SignatureID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.10": { "d": "pkcs-12Version1", "c": "", "w": false },
"1.2.840.113549.1.12.10.1": { "d": "pkcs-12BadIds", "c": "", "w": false },
"1.2.840.113549.1.12.10.1.1": { "d": "pkcs-12-keyBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.2": { "d": "pkcs-12-pkcs-8ShroudedKeyBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.3": { "d": "pkcs-12-certBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.4": { "d": "pkcs-12-crlBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.5": { "d": "pkcs-12-secretBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.6": { "d": "pkcs-12-safeContentsBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.15.1": { "d": "pkcs15modules", "c": "PKCS #15", "w": false },
"1.2.840.113549.1.15.2": { "d": "pkcs15attributes", "c": "PKCS #15", "w": false },
"1.2.840.113549.1.15.3": { "d": "pkcs15contentType", "c": "PKCS #15", "w": false },
"1.2.840.113549.1.15.3.1": { "d": "pkcs15content", "c": "PKCS #15 content type", "w": false },
"1.2.840.113549.2": { "d": "digestAlgorithm", "c": "", "w": false },
"1.2.840.113549.2.2": { "d": "md2", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.4": { "d": "md4", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.5": { "d": "md5", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.7": { "d": "hmacWithSHA1", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.8": { "d": "hmacWithSHA224", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.9": { "d": "hmacWithSHA256", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.10": { "d": "hmacWithSHA384", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.11": { "d": "hmacWithSHA512", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.3": { "d": "encryptionAlgorithm", "c": "", "w": false },
"1.2.840.113549.3.2": { "d": "rc2CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.3": { "d": "rc2ECB", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.4": { "d": "rc4", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.5": { "d": "rc4WithMAC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.6": { "d": "desx-CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.7": { "d": "des-EDE3-CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.8": { "d": "rc5CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.9": { "d": "rc5-CBCPad", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.10": { "d": "desCDMF", "c": "RSADSI encryptionAlgorithm. Formerly called CDMFCBCPad", "w": false },
"1.2.840.114021.1.6.1": { "d": "Identrus unknown policyIdentifier", "c": "Identrus", "w": false },
"1.2.840.114021.4.1": { "d": "identrusOCSP", "c": "Identrus", "w": false },
"1.2.840.113556.1.2.241": { "d": "deliveryMechanism", "c": "Microsoft Exchange Server - attribute", "w": false },
"1.2.840.113556.1.3.0": { "d": "site-Addressing", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.13": { "d": "classSchema", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.14": { "d": "attributeSchema", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.17": { "d": "mailbox-Agent", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.22": { "d": "mailbox", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.23": { "d": "container", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.46": { "d": "mailRecipient", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.2.281": { "d": "ntSecurityDescriptor", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.145": { "d": "revision", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1327": { "d": "pKIDefaultKeySpec", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1328": { "d": "pKIKeyUsage", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1329": { "d": "pKIMaxIssuingDepth", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1330": { "d": "pKICriticalExtensions", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1331": { "d": "pKIExpirationPeriod", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1332": { "d": "pKIOverlapPeriod", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1333": { "d": "pKIExtendedKeyUsage", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1334": { "d": "pKIDefaultCSPs", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1335": { "d": "pKIEnrollmentAccess", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1429": { "d": "msPKI-RA-Signature", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1430": { "d": "msPKI-Enrollment-Flag", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1431": { "d": "msPKI-Private-Key-Flag", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1432": { "d": "msPKI-Certificate-Name-Flag", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1433": { "d": "msPKI-Minimal-Key-Size", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1434": { "d": "msPKI-Template-Schema-Version", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1435": { "d": "msPKI-Template-Minor-Revision", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1436": { "d": "msPKI-Cert-Template-OID", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1437": { "d": "msPKI-Supersede-Templates", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1438": { "d": "msPKI-RA-Policies", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1439": { "d": "msPKI-Certificate-Policy", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1674": { "d": "msPKI-Certificate-Application-Policy", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1675": { "d": "msPKI-RA-Application-Policies", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.4.3": { "d": "microsoftExcel", "c": "Microsoft", "w": false },
"1.2.840.113556.4.4": { "d": "titledWithOID", "c": "Microsoft", "w": false },
"1.2.840.113556.4.5": { "d": "microsoftPowerPoint", "c": "Microsoft", "w": false },
"1.2.840.113583.1": { "d": "adobeAcrobat", "c": "Adobe Acrobat", "w": false },
"1.2.840.113583.1.1": { "d": "acrobatSecurity", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.1": { "d": "pdfPassword", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.2": { "d": "pdfDefaultSigningCredential", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.3": { "d": "pdfDefaultEncryptionCredential", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.4": { "d": "pdfPasswordTimeout", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.5": { "d": "pdfAuthenticDocumentsTrust", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.6": { "d": "pdfDynamicContentTrust", "c": "Adobe Acrobat security", "w": true },
"1.2.840.113583.1.1.7": { "d": "pdfUbiquityTrust", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.8": { "d": "pdfRevocationInfoArchival", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.9": { "d": "pdfX509Extension", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.9.1": { "d": "pdfTimeStamp", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.9.2": { "d": "pdfArchiveRevInfo", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.1.10": { "d": "pdfPPLKLiteCredential", "c": "Adobe Acrobat security", "w": false },
"1.2.840.113583.1.2.": { "d": "acrobatCPS", "c": "Adobe Acrobat CPS", "w": false },
"1.2.840.113583.1.2.1": { "d": "pdfAuthenticDocumentsCPS", "c": "Adobe Acrobat CPS", "w": false },
"1.2.840.113583.1.2.2": { "d": "pdfTestCPS", "c": "Adobe Acrobat CPS", "w": false },
"1.2.840.113583.1.2.3": { "d": "pdfUbiquityCPS", "c": "Adobe Acrobat CPS", "w": false },
"1.2.840.113583.1.2.4": { "d": "pdfAdhocCPS", "c": "Adobe Acrobat CPS", "w": false },
"1.2.840.113583.1.7": { "d": "acrobatUbiquity", "c": "Adobe Acrobat ubiquity", "w": false },
"1.2.840.113583.1.7.1": { "d": "pdfUbiquitySubRights", "c": "Adobe Acrobat ubiquity", "w": false },
"1.2.840.113583.1.9": { "d": "acrobatExtension", "c": "Adobe Acrobat X.509 extension", "w": false },
"1.2.840.113628.114.1.7": { "d": "adobePKCS7", "c": "Adobe", "w": false },
"1.2.840.113635.100": { "d": "appleDataSecurity", "c": "Apple", "w": false },
"1.2.840.113635.100.1": { "d": "appleTrustPolicy", "c": "Apple", "w": false },
"1.2.840.113635.100.1.1": { "d": "appleISignTP", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.2": { "d": "appleX509Basic", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.3": { "d": "appleSSLPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.4": { "d": "appleLocalCertGenPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.5": { "d": "appleCSRGenPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.6": { "d": "appleCRLPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.7": { "d": "appleOCSPPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.8": { "d": "appleSMIMEPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.9": { "d": "appleEAPPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.10": { "d": "appleSWUpdateSigningPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.11": { "d": "appleIPSecPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.12": { "d": "appleIChatPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.13": { "d": "appleResourceSignPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.14": { "d": "applePKINITClientPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.15": { "d": "applePKINITServerPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.16": { "d": "appleCodeSigningPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.1.17": { "d": "applePackageSigningPolicy", "c": "Apple trust policy", "w": false },
"1.2.840.113635.100.2": { "d": "appleSecurityAlgorithm", "c": "Apple", "w": false },
"1.2.840.113635.100.2.1": { "d": "appleFEE", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.2.2": { "d": "appleASC", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.2.3": { "d": "appleFEE_MD5", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.2.4": { "d": "appleFEE_SHA1", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.2.5": { "d": "appleFEED", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.2.6": { "d": "appleFEEDEXP", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.2.7": { "d": "appleECDSA", "c": "Apple security algorithm", "w": false },
"1.2.840.113635.100.3": { "d": "appleDotMacCertificate", "c": "Apple", "w": false },
"1.2.840.113635.100.3.1": { "d": "appleDotMacCertificateRequest", "c": "Apple dotMac certificate", "w": false },
"1.2.840.113635.100.3.2": { "d": "appleDotMacCertificateExtension", "c": "Apple dotMac certificate", "w": false },
"1.2.840.113635.100.3.3": { "d": "appleDotMacCertificateRequestValues", "c": "Apple dotMac certificate", "w": false },
"1.2.840.113635.100.4": { "d": "appleExtendedKeyUsage", "c": "Apple", "w": false },
"1.2.840.113635.100.4.1": { "d": "appleCodeSigning", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.1.1": { "d": "appleCodeSigningDevelopment", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.1.2": { "d": "appleSoftwareUpdateSigning", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.1.3": { "d": "appleCodeSigningThirdParty", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.1.4": { "d": "appleResourceSigning", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.2": { "d": "appleIChatSigning", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.3": { "d": "appleIChatEncryption", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.4": { "d": "appleSystemIdentity", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.5": { "d": "appleCryptoEnv", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.5.1": { "d": "appleCryptoProductionEnv", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.5.2": { "d": "appleCryptoMaintenanceEnv", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.5.3": { "d": "appleCryptoTestEnv", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.5.4": { "d": "appleCryptoDevelopmentEnv", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.6": { "d": "appleCryptoQoS", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.6.1": { "d": "appleCryptoTier0QoS", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.6.2": { "d": "appleCryptoTier1QoS", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.6.3": { "d": "appleCryptoTier2QoS", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.4.6.4": { "d": "appleCryptoTier3QoS", "c": "Apple extended key usage", "w": false },
"1.2.840.113635.100.5": { "d": "appleCertificatePolicies", "c": "Apple", "w": false },
"1.2.840.113635.100.5.1": { "d": "appleCertificatePolicyID", "c": "Apple", "w": false },
"1.2.840.113635.100.5.2": { "d": "appleDotMacCertificatePolicyID", "c": "Apple", "w": false },
"1.2.840.113635.100.5.3": { "d": "appleADCCertificatePolicyID", "c": "Apple", "w": false },
"1.2.840.113635.100.6": { "d": "appleCertificateExtensions", "c": "Apple", "w": false },
"1.2.840.113635.100.6.1": { "d": "appleCertificateExtensionCodeSigning", "c": "Apple certificate extension", "w": false },
"1.2.840.113635.100.6.1.1": { "d": "appleCertificateExtensionAppleSigning", "c": "Apple certificate extension", "w": false },
"1.2.840.113635.100.6.1.2": { "d": "appleCertificateExtensionADCDeveloperSigning", "c": "Apple certificate extension", "w": false },
"1.2.840.113635.100.6.1.3": { "d": "appleCertificateExtensionADCAppleSigning", "c": "Apple certificate extension", "w": false },
"1.3.6.1.4.1.311.2.1.4": { "d": "spcIndirectDataContext", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.10": { "d": "spcAgencyInfo", "c": "Microsoft code signing. Also known as policyLink", "w": false },
"1.3.6.1.4.1.311.2.1.11": { "d": "spcStatementType", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.12": { "d": "spcSpOpusInfo", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.14": { "d": "certReqExtensions", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.15": { "d": "spcPEImageData", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.18": { "d": "spcRawFileData", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.19": { "d": "spcStructuredStorageData", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.20": { "d": "spcJavaClassData (type 1)", "c": "Microsoft code signing. Formerly \"link extension\" aka \"glue extension\"", "w": false },
"1.3.6.1.4.1.311.2.1.21": { "d": "individualCodeSigning", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.22": { "d": "commercialCodeSigning", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.25": { "d": "spcLink (type 2)", "c": "Microsoft code signing. Also known as \"glue extension\"", "w": false },
"1.3.6.1.4.1.311.2.1.26": { "d": "spcMinimalCriteriaInfo", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.27": { "d": "spcFinancialCriteriaInfo", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.28": { "d": "spcLink (type 3)", "c": "Microsoft code signing.  Also known as \"glue extension\"", "w": false },
"1.3.6.1.4.1.311.3.2.1": { "d": "timestampRequest", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.10.1": { "d": "certTrustList", "c": "Microsoft contentType", "w": false },
"1.3.6.1.4.1.311.10.1.1": { "d": "sortedCtl", "c": "Microsoft contentType", "w": false },
"1.3.6.1.4.1.311.10.2": { "d": "nextUpdateLocation", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.3.1": { "d": "certTrustListSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.2": { "d": "timeStampSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.3": { "d": "serverGatedCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.3.1": { "d": "serialized", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.3.4": { "d": "encryptedFileSystem", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.5": { "d": "whqlCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.6": { "d": "nt5Crypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.7": { "d": "oemWHQLCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.8": { "d": "embeddedNTCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.9": { "d": "rootListSigner", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.10": { "d": "qualifiedSubordination", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.11": { "d": "keyRecovery", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.12": { "d": "documentSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.13": { "d": "lifetimeSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.14": { "d": "mobileDeviceSoftware", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.15": { "d": "smartDisplay", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.16": { "d": "cspSignature", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.4.1": { "d": "efsRecovery", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.4.1": { "d": "yesnoTrustAttr", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.5.1": { "d": "drm", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.5.2": { "d": "drmIndividualization", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.6.1": { "d": "licenses", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.6.2": { "d": "licenseServer", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.7.1": { "d": "keyidRdn", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.8.1": { "d": "removeCertificate", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.9.1": { "d": "crossCertDistPoints", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.10.1": { "d": "cmcAddAttributes", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11": { "d": "certPropIdPrefix", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.4": { "d": "certMd5HashPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.20": { "d": "certKeyIdentifierPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.28": { "d": "certIssuerSerialNumberMd5HashPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.29": { "d": "certSubjectNameMd5HashPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.12.1": { "d": "anyApplicationPolicy", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.1": { "d": "renewalCertificate", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.2.1": { "d": "enrolmentNameValuePair", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.2.2": { "d": "enrolmentCSP", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.2.3": { "d": "osVersion", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.16.4": { "d": "microsoftRecipientInfo", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.17.1": { "d": "pkcs12KeyProviderNameAttr", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.17.2": { "d": "localMachineKeyset", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.17.3": { "d": "pkcs12ExtendedAttributes", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.20.1": { "d": "autoEnrollCtlUsage", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.20.2": { "d": "enrollCerttypeExtension", "c": "Microsoft CAPICOM certificate template, V1", "w": false },
"1.3.6.1.4.1.311.20.2.1": { "d": "enrollmentAgent", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.20.2.2": { "d": "smartcardLogon", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.20.2.3": { "d": "universalPrincipalName", "c": "Microsoft UPN", "w": false },
"1.3.6.1.4.1.311.20.3": { "d": "certManifold", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.1": { "d": "cAKeyCertIndexPair", "c": "Microsoft attribute.  Also known as certsrvCaVersion", "w": false },
"1.3.6.1.4.1.311.21.5": { "d": "caExchange", "c": "Microsoft extended key usage", "w": true },
"1.3.6.1.4.1.311.21.2": { "d": "certSrvPreviousCertHash", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.3": { "d": "crlVirtualBase", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.4": { "d": "crlNextPublish", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.6": { "d": "keyRecovery", "c": "Microsoft extended key usage", "w": true },
"1.3.6.1.4.1.311.21.7": { "d": "certificateTemplate", "c": "Microsoft CAPICOM certificate template, V2", "w": false },
"1.3.6.1.4.1.311.21.9": { "d": "rdnDummySigner", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.10": { "d": "applicationCertPolicies", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.11": { "d": "applicationPolicyMappings", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.12": { "d": "applicationPolicyConstraints", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.13": { "d": "archivedKey", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.21.14": { "d": "crlSelfCDP", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.15": { "d": "requireCertChainPolicy", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.16": { "d": "archivedKeyCertHash", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.17": { "d": "issuedCertHash", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.19": { "d": "dsEmailReplication", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.20": { "d": "requestClientInfo", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.21.21": { "d": "encryptedKeyHash", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.21.22": { "d": "certsrvCrossCaVersion", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.25.1": { "d": "ntdsReplication", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.31.1": { "d": "productUpdate", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.47.1.1": { "d": "systemHealth", "c": "Microsoft extended key usage", "w": false },
"1.3.6.1.4.1.311.47.1.3": { "d": "systemHealthLoophole", "c": "Microsoft extended key usage", "w": false },
"1.3.6.1.4.1.311.60.1.1": { "d": "rootProgramFlags", "c": "Microsoft policy attribute", "w": false },
"1.3.6.1.4.1.311.61.1.1": { "d": "kernelModeCodeSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.60.2.1.1": { "d": "jurisdictionOfIncorporationL", "c": "Microsoft (???)", "w": false },
"1.3.6.1.4.1.311.60.2.1.2": { "d": "jurisdictionOfIncorporationSP", "c": "Microsoft (???)", "w": false },
"1.3.6.1.4.1.311.60.2.1.3": { "d": "jurisdictionOfIncorporationC", "c": "Microsoft (???)", "w": false },
"1.3.6.1.4.1.311.88.2.1": { "d": "originalFilename", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.188.7.1.1": { "d": "ascom", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.1": { "d": "ideaECB", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.2": { "d": "ideaCBC", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.3": { "d": "ideaCFB", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.4": { "d": "ideaOFB", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.2428.10.1.1": { "d": "UNINETT policyIdentifier", "c": "UNINETT PCA", "w": false },
"1.3.6.1.4.1.2712.10": { "d": "ICE-TEL policyIdentifier", "c": "ICE-TEL CA", "w": false },
"1.3.6.1.4.1.2786.1.1.1": { "d": "ICE-TEL Italian policyIdentifier", "c": "ICE-TEL CA policy", "w": false },
"1.3.6.1.4.1.3029.1.1.1": { "d": "blowfishECB", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.1.2": { "d": "blowfishCBC", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.1.3": { "d": "blowfishCFB", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.1.4": { "d": "blowfishOFB", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.2.1": { "d": "elgamal", "c": "cryptlib public-key algorithm", "w": false },
"1.3.6.1.4.1.3029.1.2.1.1": { "d": "elgamalWithSHA-1", "c": "cryptlib public-key algorithm", "w": false },
"1.3.6.1.4.1.3029.1.2.1.2": { "d": "elgamalWithRIPEMD-160", "c": "cryptlib public-key algorithm", "w": false },
"1.3.6.1.4.1.3029.3.1.1": { "d": "cryptlibPresenceCheck", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.3.1.2": { "d": "pkiBoot", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.3.1.4": { "d": "crlExtReason", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.3.1.5": { "d": "keyFeatures", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.4.1": { "d": "cryptlibContent", "c": "cryptlib", "w": false },
"1.3.6.1.4.1.3029.4.1.1": { "d": "cryptlibConfigData", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.2": { "d": "cryptlibUserIndex", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.3": { "d": "cryptlibUserInfo", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.4": { "d": "rtcsRequest", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.5": { "d": "rtcsResponse", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.6": { "d": "rtcsResponseExt", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.42.11172.1": { "d": "mpeg-1", "c": "cryptlib special MPEG-of-cat OID", "w": false },
"1.3.6.1.4.1.3029.54.11940.54": { "d": "TSA policy \"Anything that arrives, we sign\"", "c": "cryptlib TSA policy", "w": false },
"1.3.6.1.4.1.3029.88.89.90.90.89": { "d": "xYZZY policyIdentifier", "c": "cryptlib certificate policy", "w": false },
"1.3.6.1.4.1.3401.8.1.1": { "d": "pgpExtension", "c": "PGP key information", "w": false },
"1.3.6.1.4.1.3576.7": { "d": "eciaAscX12Edi", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.1": { "d": "plainEDImessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.2": { "d": "signedEDImessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.5": { "d": "integrityEDImessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.65": { "d": "iaReceiptMessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.97": { "d": "iaStatusMessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.8": { "d": "eciaEdifact", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.9": { "d": "eciaNonEdi", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.4146": { "d": "Globalsign", "c": "Globalsign", "w": false },
"1.3.6.1.4.1.4146.1": { "d": "globalsignPolicy", "c": "Globalsign", "w": false },
"1.3.6.1.4.1.4146.1.10": { "d": "globalsignDVPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.20": { "d": "globalsignOVPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.30": { "d": "globalsignTSAPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.40": { "d": "globalsignClientCertPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.50": { "d": "globalsignCodeSignPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.60": { "d": "globalsignRootSignPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.70": { "d": "globalsignTrustedRootPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.80": { "d": "globalsignEDIClientPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.81": { "d": "globalsignEDIServerPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.90": { "d": "globalsignTPMRootPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.4146.1.95": { "d": "globalsignOCSPPolicy", "c": "Globalsign policy", "w": false },
"1.3.6.1.4.1.5309.1": { "d": "edelWebPolicy", "c": "EdelWeb policy", "w": false },
"1.3.6.1.4.1.5309.1.2": { "d": "edelWebCustomerPolicy", "c": "EdelWeb policy", "w": false },
"1.3.6.1.4.1.5309.1.2.1": { "d": "edelWebClepsydrePolicy", "c": "EdelWeb policy", "w": false },
"1.3.6.1.4.1.5309.1.2.2": { "d": "edelWebExperimentalTSAPolicy", "c": "EdelWeb policy", "w": false },
"1.3.6.1.4.1.5309.1.2.3": { "d": "edelWebOpenEvidenceTSAPolicy", "c": "EdelWeb policy", "w": false },
"1.3.6.1.4.1.5472": { "d": "timeproof", "c": "enterprise", "w": false },
"1.3.6.1.4.1.5472.1": { "d": "tss", "c": "timeproof", "w": false },
"1.3.6.1.4.1.5472.1.1": { "d": "tss80", "c": "timeproof TSS", "w": false },
"1.3.6.1.4.1.5472.1.2": { "d": "tss380", "c": "timeproof TSS", "w": false },
"1.3.6.1.4.1.5472.1.3": { "d": "tss400", "c": "timeproof TSS", "w": false },
"1.3.6.1.4.1.5770.0.3": { "d": "secondaryPractices", "c": "MEDePass", "w": false },
"1.3.6.1.4.1.5770.0.4": { "d": "physicianIdentifiers", "c": "MEDePass", "w": false },
"1.3.6.1.4.1.6449.1.2.1.3.1": { "d": "comodoPolicy", "c": "Comodo CA", "w": false },
"1.3.6.1.4.1.6449.1.2.2.15": { "d": "wotrustPolicy", "c": "WoTrust (Comodo) CA", "w": false },
"1.3.6.1.4.1.6449.1.3.5.2": { "d": "comodoCertifiedDeliveryService", "c": "Comodo CA", "w": false },
"1.3.6.1.4.1.6449.2.1.1": { "d": "comodoTimestampingPolicy", "c": "Comodo CA", "w": false },
"1.3.6.1.4.1.8301.3.5.1": { "d": "validityModelChain", "c": "TU Darmstadt ValidityModel", "w": false },
"1.3.6.1.4.1.8301.3.5.2": { "d": "validityModelShell", "c": "ValidityModel", "w": false },
"1.3.6.1.4.1.8231.1": { "d": "rolUnicoNacional", "c": "Chilean Government national unique roll number", "w": false },
"1.3.6.1.4.1.11591": { "d": "gnu", "c": "GNU Project (see http://www.gnupg.org/oids.html)", "w": false },
"1.3.6.1.4.1.11591.1": { "d": "gnuRadius", "c": "GNU Radius", "w": false },
"1.3.6.1.4.1.11591.3": { "d": "gnuRadar", "c": "GNU Radar", "w": false },
"1.3.6.1.4.1.11591.12": { "d": "gnuDigestAlgorithm", "c": "GNU digest algorithm", "w": false },
"1.3.6.1.4.1.11591.12.2": { "d": "tiger", "c": "GNU digest algorithm", "w": false },
"1.3.6.1.4.1.11591.13": { "d": "gnuEncryptionAlgorithm", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2": { "d": "serpent", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.1": { "d": "serpent128_ECB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.2": { "d": "serpent128_CBC", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.3": { "d": "serpent128_OFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.4": { "d": "serpent128_CFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.21": { "d": "serpent192_ECB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.22": { "d": "serpent192_CBC", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.23": { "d": "serpent192_OFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.24": { "d": "serpent192_CFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.41": { "d": "serpent256_ECB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.42": { "d": "serpent256_CBC", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.43": { "d": "serpent256_OFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.44": { "d": "serpent256_CFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.16334.509.1.1": { "d": "Northrop Grumman extKeyUsage?", "c": "Northrop Grumman extended key usage", "w": false },
"1.3.6.1.4.1.16334.509.2.1": { "d": "ngcClass1", "c": "Northrop Grumman policy", "w": false },
"1.3.6.1.4.1.16334.509.2.2": { "d": "ngcClass2", "c": "Northrop Grumman policy", "w": false },
"1.3.6.1.4.1.16334.509.2.3": { "d": "ngcClass3", "c": "Northrop Grumman policy", "w": false },
"1.3.6.1.4.1.23629.1.4.2.1.1": { "d": "safenetUsageLimit", "c": "SafeNet", "w": false },
"1.3.6.1.4.1.23629.1.4.2.1.2": { "d": "safenetEndDate", "c": "SafeNet", "w": false },
"1.3.6.1.4.1.23629.1.4.2.1.3": { "d": "safenetStartDate", "c": "SafeNet", "w": false },
"1.3.6.1.4.1.23629.1.4.2.1.4": { "d": "safenetAdminCert", "c": "SafeNet", "w": false },
"1.3.6.1.4.1.23629.1.4.2.2.1": { "d": "safenetKeyDigest", "c": "SafeNet", "w": false },
"1.3.6.1.5.5.7": { "d": "pkix", "c": "", "w": false },
"1.3.6.1.5.5.7.0.12": { "d": "attributeCert", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.1": { "d": "privateExtension", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.1.1": { "d": "authorityInfoAccess", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.2": { "d": "biometricInfo", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.3": { "d": "qcStatements", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.4": { "d": "acAuditIdentity", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.5": { "d": "acTargeting", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.6": { "d": "acAaControls", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.7": { "d": "ipAddrBlocks", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.8": { "d": "autonomousSysIds", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.9": { "d": "routerIdentifier", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.10": { "d": "acProxying", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.11": { "d": "subjectInfoAccess", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.12": { "d": "logoType", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.13": { "d": "wlanSSID", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.2": { "d": "policyQualifierIds", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.2.1": { "d": "cps", "c": "PKIX policy qualifier", "w": false },
"1.3.6.1.5.5.7.2.2": { "d": "unotice", "c": "PKIX policy qualifier", "w": false },
"1.3.6.1.5.5.7.2.3": { "d": "textNotice", "c": "PKIX policy qualifier", "w": false },
"1.3.6.1.5.5.7.3": { "d": "keyPurpose", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.3.1": { "d": "serverAuth", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.2": { "d": "clientAuth", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.3": { "d": "codeSigning", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.4": { "d": "emailProtection", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.5": { "d": "ipsecEndSystem", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.6": { "d": "ipsecTunnel", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.7": { "d": "ipsecUser", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.8": { "d": "timeStamping", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.9": { "d": "ocspSigning", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.10": { "d": "dvcs", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.11": { "d": "sbgpCertAAServerAuth", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.13": { "d": "eapOverPPP", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.14": { "d": "eapOverLAN", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.4": { "d": "cmpInformationTypes", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.4.1": { "d": "caProtEncCert", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.2": { "d": "signKeyPairTypes", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.3": { "d": "encKeyPairTypes", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.4": { "d": "preferredSymmAlg", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.5": { "d": "caKeyUpdateInfo", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.6": { "d": "currentCRL", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.7": { "d": "unsupportedOIDs", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.10": { "d": "keyPairParamReq", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.11": { "d": "keyPairParamRep", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.12": { "d": "revPassphrase", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.13": { "d": "implicitConfirm", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.14": { "d": "confirmWaitTime", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.15": { "d": "origPKIMessage", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.16": { "d": "suppLangTags", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.5": { "d": "crmfRegistration", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.5.1": { "d": "regCtrl", "c": "PKIX CRMF registration", "w": false },
"1.3.6.1.5.5.7.5.1.1": { "d": "regToken", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.2": { "d": "authenticator", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.3": { "d": "pkiPublicationInfo", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.4": { "d": "pkiArchiveOptions", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.5": { "d": "oldCertID", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.6": { "d": "protocolEncrKey", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.7": { "d": "altCertTemplate", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.8": { "d": "wtlsTemplate", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.2": { "d": "utf8Pairs", "c": "PKIX CRMF registration", "w": false },
"1.3.6.1.5.5.7.5.2.1": { "d": "utf8Pairs", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.2.2": { "d": "certReq", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.6": { "d": "algorithms", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.6.1": { "d": "des40", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.6.2": { "d": "noSignature", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.6.3": { "d": "dh-sig-hmac-sha1", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.6.4": { "d": "dh-pop", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.7": { "d": "cmcControls", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.8": { "d": "otherNames", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.8.1": { "d": "personalData", "c": "PKIX other name", "w": false },
"1.3.6.1.5.5.7.8.2": { "d": "userGroup", "c": "PKIX other name", "w": false },
"1.3.6.1.5.5.7.8.5": { "d": "xmppAddr", "c": "PKIX other name", "w": false },
"1.3.6.1.5.5.7.9": { "d": "personalData", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.9.1": { "d": "dateOfBirth", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.2": { "d": "placeOfBirth", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.3": { "d": "gender", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.4": { "d": "countryOfCitizenship", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.5": { "d": "countryOfResidence", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.10": { "d": "attributeCertificate", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.10.1": { "d": "authenticationInfo", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.2": { "d": "accessIdentity", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.3": { "d": "chargingIdentity", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.4": { "d": "group", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.5": { "d": "role", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.6": { "d": "wlanSSID", "c": "PKIX attribute-certificate extension", "w": false },
"1.3.6.1.5.5.7.11": { "d": "personalData", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.11.1": { "d": "pkixQCSyntax-v1", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.14.2": { "d": "resourceCertificatePolicy", "c": "PKIX policies", "w": false },
"1.3.6.1.5.5.7.20": { "d": "logo", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.20.1": { "d": "logoLoyalty", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.20.2": { "d": "logoBackground", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.48.1": { "d": "ocsp", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.48.1.1": { "d": "ocspBasic", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.2": { "d": "ocspNonce", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.3": { "d": "ocspCRL", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.4": { "d": "ocspResponse", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.5": { "d": "ocspNoCheck", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.6": { "d": "ocspArchiveCutoff", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.7": { "d": "ocspServiceLocator", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.2": { "d": "caIssuers", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.3": { "d": "timeStamping", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.4": { "d": "dvcs", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.5": { "d": "caRepository", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.7": { "d": "signedObjectRepository", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.10": { "d": "rpkiManifest", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.11": { "d": "signedObject", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.8.1.1": { "d": "hmacMD5", "c": "ISAKMP HMAC algorithm", "w": false },
"1.3.6.1.5.5.8.1.2": { "d": "hmacSHA", "c": "ISAKMP HMAC algorithm", "w": false },
"1.3.6.1.5.5.8.1.3": { "d": "hmacTiger", "c": "ISAKMP HMAC algorithm", "w": false },
"1.3.6.1.5.5.8.2.2": { "d": "iKEIntermediate", "c": "IKE ???", "w": false },
"1.3.12.2.1011.7.1": { "d": "decEncryptionAlgorithm", "c": "DASS algorithm", "w": false },
"1.3.12.2.1011.7.1.2": { "d": "decDEA", "c": "DASS encryption algorithm", "w": false },
"1.3.12.2.1011.7.2": { "d": "decHashAlgorithm", "c": "DASS algorithm", "w": false },
"1.3.12.2.1011.7.2.1": { "d": "decMD2", "c": "DASS hash algorithm", "w": false },
"1.3.12.2.1011.7.2.2": { "d": "decMD4", "c": "DASS hash algorithm", "w": false },
"1.3.12.2.1011.7.3": { "d": "decSignatureAlgorithm", "c": "DASS algorithm", "w": false },
"1.3.12.2.1011.7.3.1": { "d": "decMD2withRSA", "c": "DASS signature algorithm", "w": false },
"1.3.12.2.1011.7.3.2": { "d": "decMD4withRSA", "c": "DASS signature algorithm", "w": false },
"1.3.12.2.1011.7.3.3": { "d": "decDEAMAC", "c": "DASS signature algorithm", "w": false },
"1.3.14.2.26.5": { "d": "sha", "c": "Unsure about this OID", "w": false },
"1.3.14.3.2.1.1": { "d": "rsa", "c": "X.509. Unsure about this OID", "w": false },
"1.3.14.3.2.2": { "d": "md4WitRSA", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.3": { "d": "md5WithRSA", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.4": { "d": "md4WithRSAEncryption", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.2.1": { "d": "sqmod-N", "c": "X.509. Deprecated", "w": true },
"1.3.14.3.2.3.1": { "d": "sqmod-NwithRSA", "c": "X.509. Deprecated", "w": true },
"1.3.14.3.2.6": { "d": "desECB", "c": "", "w": false },
"1.3.14.3.2.7": { "d": "desCBC", "c": "", "w": false },
"1.3.14.3.2.8": { "d": "desOFB", "c": "", "w": false },
"1.3.14.3.2.9": { "d": "desCFB", "c": "", "w": false },
"1.3.14.3.2.10": { "d": "desMAC", "c": "", "w": false },
"1.3.14.3.2.11": { "d": "rsaSignature", "c": "ISO 9796-2, also X9.31 Part 1", "w": false },
"1.3.14.3.2.12": { "d": "dsa", "c": "OIW?, supposedly from an incomplete version of SDN.701 (doesn't match final SDN.701)", "w": true },
"1.3.14.3.2.13": { "d": "dsaWithSHA", "c": "Oddball OIW OID.  Incorrectly used by JDK 1.1 in place of (1 3 14 3 2 27)", "w": true },
"1.3.14.3.2.14": { "d": "mdc2WithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.15": { "d": "shaWithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.16": { "d": "dhWithCommonModulus", "c": "Oddball OIW OID. Deprecated, use a plain DH OID instead", "w": true },
"1.3.14.3.2.17": { "d": "desEDE", "c": "Oddball OIW OID. Mode is ECB", "w": false },
"1.3.14.3.2.18": { "d": "sha", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.19": { "d": "mdc-2", "c": "Oddball OIW OID, DES-based hash, planned for X9.31 Part 2", "w": false },
"1.3.14.3.2.20": { "d": "dsaCommon", "c": "Oddball OIW OID.  Deprecated, use a plain DSA OID instead", "w": true },
"1.3.14.3.2.21": { "d": "dsaCommonWithSHA", "c": "Oddball OIW OID.  Deprecated, use a plain dsaWithSHA OID instead", "w": true },
"1.3.14.3.2.22": { "d": "rsaKeyTransport", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.23": { "d": "keyed-hash-seal", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.24": { "d": "md2WithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.25": { "d": "md5WithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.26": { "d": "SHA1", "c": "OIW", "w": false },
"1.3.14.3.2.27": { "d": "dsaWithSHA1", "c": "OIW. This OID may also be assigned as ripemd-160", "w": false },
"1.3.14.3.2.28": { "d": "dsaWithCommonSHA1", "c": "OIW", "w": false },
"1.3.14.3.2.29": { "d": "sha-1WithRSAEncryption", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.3.1": { "d": "simple-strong-auth-mechanism", "c": "Oddball OIW OID", "w": false },
"1.3.14.7.2.1.1": { "d": "ElGamal", "c": "Unsure about this OID", "w": false },
"1.3.14.7.2.3.1": { "d": "md2WithRSA", "c": "Unsure about this OID", "w": false },
"1.3.14.7.2.3.2": { "d": "md2WithElGamal", "c": "Unsure about this OID", "w": false },
"1.3.36.1": { "d": "document", "c": "Teletrust document", "w": false },
"1.3.36.1.1": { "d": "finalVersion", "c": "Teletrust document", "w": false },
"1.3.36.1.2": { "d": "draft", "c": "Teletrust document", "w": false },
"1.3.36.2": { "d": "sio", "c": "Teletrust sio", "w": false },
"1.3.36.2.1": { "d": "sedu", "c": "Teletrust sio", "w": false },
"1.3.36.3": { "d": "algorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.1": { "d": "encryptionAlgorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.1.1": { "d": "des", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.1": { "d": "desECB_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.1.1": { "d": "desECB_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.2.1": { "d": "desCBC_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.2.1.1": { "d": "desCBC_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.3": { "d": "des_3", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.3.1.1": { "d": "des_3ECB_pad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.3.1.1.1": { "d": "des_3ECB_ISOpad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.3.2.1": { "d": "des_3CBC_pad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.3.2.1.1": { "d": "des_3CBC_ISOpad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.2": { "d": "idea", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.1": { "d": "ideaECB", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.1.1": { "d": "ideaECB_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.1.1.1": { "d": "ideaECB_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.2": { "d": "ideaCBC", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.2.1": { "d": "ideaCBC_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.2.1.1": { "d": "ideaCBC_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.3": { "d": "ideaOFB", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.4": { "d": "ideaCFB", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.4": { "d": "rsaEncryption", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.4.512.17": { "d": "rsaEncryptionWithlmod512expe17", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5": { "d": "bsi-1", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5.1": { "d": "bsi_1ECB_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5.2": { "d": "bsi_1CBC_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5.2.1": { "d": "bsi_1CBC_PEMpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.2": { "d": "hashAlgorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.2.1": { "d": "ripemd160", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.2": { "d": "ripemd128", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.3": { "d": "ripemd256", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.4": { "d": "mdc2singleLength", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.5": { "d": "mdc2doubleLength", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.3": { "d": "signatureAlgorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.3.1": { "d": "rsaSignature", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.1": { "d": "rsaSignatureWithsha1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.1.1024.11": { "d": "rsaSignatureWithsha1_l1024_l11", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.2": { "d": "rsaSignatureWithripemd160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.2.1024.11": { "d": "rsaSignatureWithripemd160_l1024_l11", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.3": { "d": "rsaSignatureWithrimpemd128", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.4": { "d": "rsaSignatureWithrimpemd256", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2": { "d": "ecsieSign", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.1": { "d": "ecsieSignWithsha1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.2": { "d": "ecsieSignWithripemd160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.3": { "d": "ecsieSignWithmd2", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.4": { "d": "ecsieSignWithmd5", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.8.1.1.1": { "d": "brainpoolP160r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.2": { "d": "brainpoolP160t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.3": { "d": "brainpoolP192r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.4": { "d": "brainpoolP192t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.5": { "d": "brainpoolP224r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.6": { "d": "brainpoolP224t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.7": { "d": "brainpoolP256r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.8": { "d": "brainpoolP256t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.9": { "d": "brainpoolP320r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.10": { "d": "brainpoolP320t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.11": { "d": "brainpoolP384r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.12": { "d": "brainpoolP384t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.13": { "d": "brainpoolP512r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.14": { "d": "brainpoolP512t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.4": { "d": "signatureScheme", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.4.1": { "d": "sigS_ISO9796-1", "c": "Teletrust signature scheme", "w": false },
"1.3.36.3.4.2": { "d": "sigS_ISO9796-2", "c": "Teletrust signature scheme", "w": false },
"1.3.36.3.4.2.1": { "d": "sigS_ISO9796-2Withred", "c": "Teletrust signature scheme. Unsure what this is supposed to be", "w": false },
"1.3.36.3.4.2.2": { "d": "sigS_ISO9796-2Withrsa", "c": "Teletrust signature scheme. Unsure what this is supposed to be", "w": false },
"1.3.36.3.4.2.3": { "d": "sigS_ISO9796-2Withrnd", "c": "Teletrust signature scheme. 9796-2 with random number in padding field", "w": false },
"1.3.36.4": { "d": "attribute", "c": "Teletrust attribute", "w": false },
"1.3.36.5": { "d": "policy", "c": "Teletrust policy", "w": false },
"1.3.36.6": { "d": "api", "c": "Teletrust API", "w": false },
"1.3.36.6.1": { "d": "manufacturer-specific_api", "c": "Teletrust API", "w": false },
"1.3.36.6.1.1": { "d": "utimaco-api", "c": "Teletrust API", "w": false },
"1.3.36.6.2": { "d": "functionality-specific_api", "c": "Teletrust API", "w": false },
"1.3.36.7": { "d": "keymgmnt", "c": "Teletrust key management", "w": false },
"1.3.36.7.1": { "d": "keyagree", "c": "Teletrust key management", "w": false },
"1.3.36.7.1.1": { "d": "bsiPKE", "c": "Teletrust key management", "w": false },
"1.3.36.7.2": { "d": "keytrans", "c": "Teletrust key management", "w": false },
"1.3.36.7.2.1": { "d": "encISO9796-2Withrsa", "c": "Teletrust key management. 9796-2 with key stored in hash field", "w": false },
"1.3.36.8.1.1": { "d": "Teletrust SigGConform policyIdentifier", "c": "Teletrust policy", "w": false },
"1.3.36.8.2.1": { "d": "directoryService", "c": "Teletrust extended key usage", "w": false },
"1.3.36.8.3.1": { "d": "dateOfCertGen", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.2": { "d": "procuration", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.3": { "d": "admission", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.4": { "d": "monetaryLimit", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.5": { "d": "declarationOfMajority", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.6": { "d": "integratedCircuitCardSerialNumber", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.7": { "d": "pKReference", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.8": { "d": "restriction", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.9": { "d": "retrieveIfAllowed", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.10": { "d": "requestedCertificate", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.11": { "d": "namingAuthorities", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.11.1": { "d": "rechtWirtschaftSteuern", "c": "Teletrust naming authorities", "w": false },
"1.3.36.8.3.11.1.1": { "d": "rechtsanwaeltin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.2": { "d": "rechtsanwalt", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.3": { "d": "rechtsBeistand", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.4": { "d": "steuerBeraterin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.5": { "d": "steuerBerater", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.6": { "d": "steuerBevollmaechtigte", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.7": { "d": "steuerBevollmaechtigter", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.8": { "d": "notarin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.9": { "d": "notar", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.10": { "d": "notarVertreterin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.11": { "d": "notarVertreter", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.12": { "d": "notariatsVerwalterin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.13": { "d": "notariatsVerwalter", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.14": { "d": "wirtschaftsPrueferin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.15": { "d": "wirtschaftsPruefer", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.16": { "d": "vereidigteBuchprueferin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.17": { "d": "vereidigterBuchpruefer", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.18": { "d": "patentAnwaeltin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.19": { "d": "patentAnwalt", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.12": { "d": "certInDirSince", "c": "Teletrust OCSP attribute (obsolete)", "w": true },
"1.3.36.8.3.13": { "d": "certHash", "c": "Teletrust OCSP attribute", "w": false },
"1.3.36.8.3.14": { "d": "nameAtBirth", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.15": { "d": "additionalInformation", "c": "Teletrust attribute", "w": false },
"1.3.36.8.4.1": { "d": "personalData", "c": "Teletrust OtherName attribute", "w": false },
"1.3.36.8.4.8": { "d": "restriction", "c": "Teletrust attribute certificate attribute", "w": false },
"1.3.36.8.5.1.1.1": { "d": "rsaIndicateSHA1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.1.2": { "d": "rsaIndicateRIPEMD160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.1.3": { "d": "rsaWithSHA1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.1.4": { "d": "rsaWithRIPEMD160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.2.1": { "d": "dsaExtended", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.2.2": { "d": "dsaWithRIPEMD160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.6.1": { "d": "cert", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.2": { "d": "certRef", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.3": { "d": "attrCert", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.4": { "d": "attrRef", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.5": { "d": "fileName", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.6": { "d": "storageTime", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.7": { "d": "fileSize", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.8": { "d": "location", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.9": { "d": "sigNumber", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.10": { "d": "autoGen", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.7.1.1": { "d": "ptAdobeILL", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.2": { "d": "ptAmiPro", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.3": { "d": "ptAutoCAD", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.4": { "d": "ptBinary", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.5": { "d": "ptBMP", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.6": { "d": "ptCGM", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.7": { "d": "ptCorelCRT", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.8": { "d": "ptCorelDRW", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.9": { "d": "ptCorelEXC", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.10": { "d": "ptCorelPHT", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.11": { "d": "ptDraw", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.12": { "d": "ptDVI", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.13": { "d": "ptEPS", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.14": { "d": "ptExcel", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.15": { "d": "ptGEM", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.16": { "d": "ptGIF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.17": { "d": "ptHPGL", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.18": { "d": "ptJPEG", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.19": { "d": "ptKodak", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.20": { "d": "ptLaTeX", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.21": { "d": "ptLotus", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.22": { "d": "ptLotusPIC", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.23": { "d": "ptMacPICT", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.24": { "d": "ptMacWord", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.25": { "d": "ptMSWfD", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.26": { "d": "ptMSWord", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.27": { "d": "ptMSWord2", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.28": { "d": "ptMSWord6", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.29": { "d": "ptMSWord8", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.30": { "d": "ptPDF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.31": { "d": "ptPIF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.32": { "d": "ptPostscript", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.33": { "d": "ptRTF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.34": { "d": "ptSCITEX", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.35": { "d": "ptTAR", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.36": { "d": "ptTarga", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.37": { "d": "ptTeX", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.38": { "d": "ptText", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.39": { "d": "ptTIFF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.40": { "d": "ptTIFF-FC", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.41": { "d": "ptUID", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.42": { "d": "ptUUEncode", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.43": { "d": "ptWMF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.44": { "d": "ptWordPerfect", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.45": { "d": "ptWPGrph", "c": "Teletrust presentation types", "w": false },
"1.3.101.1.4": { "d": "thawte-ce", "c": "Thawte", "w": false },
"1.3.101.1.4.1": { "d": "strongExtranet", "c": "Thawte certificate extension", "w": false },
"1.3.132.0.1": { "d": "sect163k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.2": { "d": "sect163r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.3": { "d": "sect239k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.4": { "d": "sect113r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.5": { "d": "sect113r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.6": { "d": "secp112r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.7": { "d": "secp112r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.8": { "d": "secp160r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.9": { "d": "secp160k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.10": { "d": "secp256k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.15": { "d": "sect163r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.16": { "d": "sect283k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.17": { "d": "sect283r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.22": { "d": "sect131r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.23": { "d": "sect131r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.24": { "d": "sect193r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.25": { "d": "sect193r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.26": { "d": "sect233k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.27": { "d": "sect233r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.28": { "d": "secp128r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.29": { "d": "secp128r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.30": { "d": "secp160r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.31": { "d": "secp192k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.32": { "d": "secp224k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.33": { "d": "secp224r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.34": { "d": "secp384r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.35": { "d": "secp521r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.36": { "d": "sect409k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.37": { "d": "sect409r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.38": { "d": "sect571k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.39": { "d": "sect571r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"2.5.4.0": { "d": "objectClass", "c": "X.520 DN component", "w": false },
"2.5.4.1": { "d": "aliasedEntryName", "c": "X.520 DN component", "w": false },
"2.5.4.2": { "d": "knowledgeInformation", "c": "X.520 DN component", "w": false },
"2.5.4.3": { "d": "commonName", "c": "X.520 DN component", "w": false },
"2.5.4.4": { "d": "surname", "c": "X.520 DN component", "w": false },
"2.5.4.5": { "d": "serialNumber", "c": "X.520 DN component", "w": false },
"2.5.4.6": { "d": "countryName", "c": "X.520 DN component", "w": false },
"2.5.4.7": { "d": "localityName", "c": "X.520 DN component", "w": false },
"2.5.4.7.1": { "d": "collectiveLocalityName", "c": "X.520 DN component", "w": false },
"2.5.4.8": { "d": "stateOrProvinceName", "c": "X.520 DN component", "w": false },
"2.5.4.8.1": { "d": "collectiveStateOrProvinceName", "c": "X.520 DN component", "w": false },
"2.5.4.9": { "d": "streetAddress", "c": "X.520 DN component", "w": false },
"2.5.4.9.1": { "d": "collectiveStreetAddress", "c": "X.520 DN component", "w": false },
"2.5.4.10": { "d": "organizationName", "c": "X.520 DN component", "w": false },
"2.5.4.10.1": { "d": "collectiveOrganizationName", "c": "X.520 DN component", "w": false },
"2.5.4.11": { "d": "organizationalUnitName", "c": "X.520 DN component", "w": false },
"2.5.4.11.1": { "d": "collectiveOrganizationalUnitName", "c": "X.520 DN component", "w": false },
"2.5.4.12": { "d": "title", "c": "X.520 DN component", "w": false },
"2.5.4.13": { "d": "description", "c": "X.520 DN component", "w": false },
"2.5.4.14": { "d": "searchGuide", "c": "X.520 DN component", "w": false },
"2.5.4.15": { "d": "businessCategory", "c": "X.520 DN component", "w": false },
"2.5.4.16": { "d": "postalAddress", "c": "X.520 DN component", "w": false },
"2.5.4.16.1": { "d": "collectivePostalAddress", "c": "X.520 DN component", "w": false },
"2.5.4.17": { "d": "postalCode", "c": "X.520 DN component", "w": false },
"2.5.4.17.1": { "d": "collectivePostalCode", "c": "X.520 DN component", "w": false },
"2.5.4.18": { "d": "postOfficeBox", "c": "X.520 DN component", "w": false },
"2.5.4.18.1": { "d": "collectivePostOfficeBox", "c": "X.520 DN component", "w": false },
"2.5.4.19": { "d": "physicalDeliveryOfficeName", "c": "X.520 DN component", "w": false },
"2.5.4.19.1": { "d": "collectivePhysicalDeliveryOfficeName", "c": "X.520 DN component", "w": false },
"2.5.4.20": { "d": "telephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.20.1": { "d": "collectiveTelephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.21": { "d": "telexNumber", "c": "X.520 DN component", "w": false },
"2.5.4.21.1": { "d": "collectiveTelexNumber", "c": "X.520 DN component", "w": false },
"2.5.4.22": { "d": "teletexTerminalIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.22.1": { "d": "collectiveTeletexTerminalIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.23": { "d": "facsimileTelephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.23.1": { "d": "collectiveFacsimileTelephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.24": { "d": "x121Address", "c": "X.520 DN component", "w": false },
"2.5.4.25": { "d": "internationalISDNNumber", "c": "X.520 DN component", "w": false },
"2.5.4.25.1": { "d": "collectiveInternationalISDNNumber", "c": "X.520 DN component", "w": false },
"2.5.4.26": { "d": "registeredAddress", "c": "X.520 DN component", "w": false },
"2.5.4.27": { "d": "destinationIndicator", "c": "X.520 DN component", "w": false },
"2.5.4.28": { "d": "preferredDeliveryMehtod", "c": "X.520 DN component", "w": false },
"2.5.4.29": { "d": "presentationAddress", "c": "X.520 DN component", "w": false },
"2.5.4.30": { "d": "supportedApplicationContext", "c": "X.520 DN component", "w": false },
"2.5.4.31": { "d": "member", "c": "X.520 DN component", "w": false },
"2.5.4.32": { "d": "owner", "c": "X.520 DN component", "w": false },
"2.5.4.33": { "d": "roleOccupant", "c": "X.520 DN component", "w": false },
"2.5.4.34": { "d": "seeAlso", "c": "X.520 DN component", "w": false },
"2.5.4.35": { "d": "userPassword", "c": "X.520 DN component", "w": false },
"2.5.4.36": { "d": "userCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.37": { "d": "caCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.38": { "d": "authorityRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.39": { "d": "certificateRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.40": { "d": "crossCertificatePair", "c": "X.520 DN component", "w": false },
"2.5.4.41": { "d": "name", "c": "X.520 DN component", "w": false },
"2.5.4.42": { "d": "givenName", "c": "X.520 DN component", "w": false },
"2.5.4.43": { "d": "initials", "c": "X.520 DN component", "w": false },
"2.5.4.44": { "d": "generationQualifier", "c": "X.520 DN component", "w": false },
"2.5.4.45": { "d": "uniqueIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.46": { "d": "dnQualifier", "c": "X.520 DN component", "w": false },
"2.5.4.47": { "d": "enhancedSearchGuide", "c": "X.520 DN component", "w": false },
"2.5.4.48": { "d": "protocolInformation", "c": "X.520 DN component", "w": false },
"2.5.4.49": { "d": "distinguishedName", "c": "X.520 DN component", "w": false },
"2.5.4.50": { "d": "uniqueMember", "c": "X.520 DN component", "w": false },
"2.5.4.51": { "d": "houseIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.52": { "d": "supportedAlgorithms", "c": "X.520 DN component", "w": false },
"2.5.4.53": { "d": "deltaRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.54": { "d": "dmdName", "c": "X.520 DN component", "w": false },
"2.5.4.55": { "d": "clearance", "c": "X.520 DN component", "w": false },
"2.5.4.56": { "d": "defaultDirQop", "c": "X.520 DN component", "w": false },
"2.5.4.57": { "d": "attributeIntegrityInfo", "c": "X.520 DN component", "w": false },
"2.5.4.58": { "d": "attributeCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.59": { "d": "attributeCertificateRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.60": { "d": "confKeyInfo", "c": "X.520 DN component", "w": false },
"2.5.4.61": { "d": "aACertificate", "c": "X.520 DN component", "w": false },
"2.5.4.62": { "d": "attributeDescriptorCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.63": { "d": "attributeAuthorityRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.64": { "d": "familyInformation", "c": "X.520 DN component", "w": false },
"2.5.4.65": { "d": "pseudonym", "c": "X.520 DN component", "w": false },
"2.5.4.66": { "d": "communicationsService", "c": "X.520 DN component", "w": false },
"2.5.4.67": { "d": "communicationsNetwork", "c": "X.520 DN component", "w": false },
"2.5.4.68": { "d": "certificationPracticeStmt", "c": "X.520 DN component", "w": false },
"2.5.4.69": { "d": "certificatePolicy", "c": "X.520 DN component", "w": false },
"2.5.4.70": { "d": "pkiPath", "c": "X.520 DN component", "w": false },
"2.5.4.71": { "d": "privPolicy", "c": "X.520 DN component", "w": false },
"2.5.4.72": { "d": "role", "c": "X.520 DN component", "w": false },
"2.5.4.73": { "d": "delegationPath", "c": "X.520 DN component", "w": false },
"2.5.4.74": { "d": "protPrivPolicy", "c": "X.520 DN component", "w": false },
"2.5.4.75": { "d": "xMLPrivilegeInfo", "c": "X.520 DN component", "w": false },
"2.5.4.76": { "d": "xmlPrivPolicy", "c": "X.520 DN component", "w": false },
"2.5.4.82": { "d": "permission", "c": "X.520 DN component", "w": false },
"2.5.6.0": { "d": "top", "c": "X.520 objectClass", "w": false },
"2.5.6.1": { "d": "alias", "c": "X.520 objectClass", "w": false },
"2.5.6.2": { "d": "country", "c": "X.520 objectClass", "w": false },
"2.5.6.3": { "d": "locality", "c": "X.520 objectClass", "w": false },
"2.5.6.4": { "d": "organization", "c": "X.520 objectClass", "w": false },
"2.5.6.5": { "d": "organizationalUnit", "c": "X.520 objectClass", "w": false },
"2.5.6.6": { "d": "person", "c": "X.520 objectClass", "w": false },
"2.5.6.7": { "d": "organizationalPerson", "c": "X.520 objectClass", "w": false },
"2.5.6.8": { "d": "organizationalRole", "c": "X.520 objectClass", "w": false },
"2.5.6.9": { "d": "groupOfNames", "c": "X.520 objectClass", "w": false },
"2.5.6.10": { "d": "residentialPerson", "c": "X.520 objectClass", "w": false },
"2.5.6.11": { "d": "applicationProcess", "c": "X.520 objectClass", "w": false },
"2.5.6.12": { "d": "applicationEntity", "c": "X.520 objectClass", "w": false },
"2.5.6.13": { "d": "dSA", "c": "X.520 objectClass", "w": false },
"2.5.6.14": { "d": "device", "c": "X.520 objectClass", "w": false },
"2.5.6.15": { "d": "strongAuthenticationUser", "c": "X.520 objectClass", "w": false },
"2.5.6.16": { "d": "certificateAuthority", "c": "X.520 objectClass", "w": false },
"2.5.6.17": { "d": "groupOfUniqueNames", "c": "X.520 objectClass", "w": false },
"2.5.6.21": { "d": "pkiUser", "c": "X.520 objectClass", "w": false },
"2.5.6.22": { "d": "pkiCA", "c": "X.520 objectClass", "w": false },
"2.5.8.1.1": { "d": "rsa", "c": "X.500 algorithms.  Ambiguous, since no padding rules specified", "w": true },
"2.5.29.1": { "d": "authorityKeyIdentifier", "c": "X.509 extension.  Deprecated, use 2 5 29 35 instead", "w": true },
"2.5.29.2": { "d": "keyAttributes", "c": "X.509 extension.  Obsolete, use keyUsage/extKeyUsage instead", "w": true },
"2.5.29.3": { "d": "certificatePolicies", "c": "X.509 extension.  Deprecated, use 2 5 29 32 instead", "w": true },
"2.5.29.4": { "d": "keyUsageRestriction", "c": "X.509 extension.  Obsolete, use keyUsage/extKeyUsage instead", "w": true },
"2.5.29.5": { "d": "policyMapping", "c": "X.509 extension.  Deprecated, use 2 5 29 33 instead", "w": true },
"2.5.29.6": { "d": "subtreesConstraint", "c": "X.509 extension.  Obsolete, use nameConstraints instead", "w": true },
"2.5.29.7": { "d": "subjectAltName", "c": "X.509 extension.  Deprecated, use 2 5 29 17 instead", "w": true },
"2.5.29.8": { "d": "issuerAltName", "c": "X.509 extension.  Deprecated, use 2 5 29 18 instead", "w": true },
"2.5.29.9": { "d": "subjectDirectoryAttributes", "c": "X.509 extension", "w": false },
"2.5.29.10": { "d": "basicConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 19 instead", "w": true },
"2.5.29.11": { "d": "nameConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 30 instead", "w": true },
"2.5.29.12": { "d": "policyConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 36 instead", "w": true },
"2.5.29.13": { "d": "basicConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 19 instead", "w": true },
"2.5.29.14": { "d": "subjectKeyIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.15": { "d": "keyUsage", "c": "X.509 extension", "w": false },
"2.5.29.16": { "d": "privateKeyUsagePeriod", "c": "X.509 extension", "w": false },
"2.5.29.17": { "d": "subjectAltName", "c": "X.509 extension", "w": false },
"2.5.29.18": { "d": "issuerAltName", "c": "X.509 extension", "w": false },
"2.5.29.19": { "d": "basicConstraints", "c": "X.509 extension", "w": false },
"2.5.29.20": { "d": "cRLNumber", "c": "X.509 extension", "w": false },
"2.5.29.21": { "d": "cRLReason", "c": "X.509 extension", "w": false },
"2.5.29.22": { "d": "expirationDate", "c": "X.509 extension.  Deprecated, alternative OID uncertain", "w": true },
"2.5.29.23": { "d": "instructionCode", "c": "X.509 extension", "w": false },
"2.5.29.24": { "d": "invalidityDate", "c": "X.509 extension", "w": false },
"2.5.29.25": { "d": "cRLDistributionPoints", "c": "X.509 extension.  Deprecated, use 2 5 29 31 instead", "w": true },
"2.5.29.26": { "d": "issuingDistributionPoint", "c": "X.509 extension.  Deprecated, use 2 5 29 28 instead", "w": true },
"2.5.29.27": { "d": "deltaCRLIndicator", "c": "X.509 extension", "w": false },
"2.5.29.28": { "d": "issuingDistributionPoint", "c": "X.509 extension", "w": false },
"2.5.29.29": { "d": "certificateIssuer", "c": "X.509 extension", "w": false },
"2.5.29.30": { "d": "nameConstraints", "c": "X.509 extension", "w": false },
"2.5.29.31": { "d": "cRLDistributionPoints", "c": "X.509 extension", "w": false },
"2.5.29.32": { "d": "certificatePolicies", "c": "X.509 extension", "w": false },
"2.5.29.32.0": { "d": "anyPolicy", "c": "X.509 certificate policy", "w": false },
"2.5.29.33": { "d": "policyMappings", "c": "X.509 extension", "w": false },
"2.5.29.34": { "d": "policyConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 36 instead", "w": true },
"2.5.29.35": { "d": "authorityKeyIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.36": { "d": "policyConstraints", "c": "X.509 extension", "w": false },
"2.5.29.37": { "d": "extKeyUsage", "c": "X.509 extension", "w": false },
"2.5.29.37.0": { "d": "anyExtendedKeyUsage", "c": "X.509 extended key usage", "w": false },
"2.5.29.38": { "d": "authorityAttributeIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.39": { "d": "roleSpecCertIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.40": { "d": "cRLStreamIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.41": { "d": "basicAttConstraints", "c": "X.509 extension", "w": false },
"2.5.29.42": { "d": "delegatedNameConstraints", "c": "X.509 extension", "w": false },
"2.5.29.43": { "d": "timeSpecification", "c": "X.509 extension", "w": false },
"2.5.29.44": { "d": "cRLScope", "c": "X.509 extension", "w": false },
"2.5.29.45": { "d": "statusReferrals", "c": "X.509 extension", "w": false },
"2.5.29.46": { "d": "freshestCRL", "c": "X.509 extension", "w": false },
"2.5.29.47": { "d": "orderedList", "c": "X.509 extension", "w": false },
"2.5.29.48": { "d": "attributeDescriptor", "c": "X.509 extension", "w": false },
"2.5.29.49": { "d": "userNotice", "c": "X.509 extension", "w": false },
"2.5.29.50": { "d": "sOAIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.51": { "d": "baseUpdateTime", "c": "X.509 extension", "w": false },
"2.5.29.52": { "d": "acceptableCertPolicies", "c": "X.509 extension", "w": false },
"2.5.29.53": { "d": "deltaInfo", "c": "X.509 extension", "w": false },
"2.5.29.54": { "d": "inhibitAnyPolicy", "c": "X.509 extension", "w": false },
"2.5.29.55": { "d": "targetInformation", "c": "X.509 extension", "w": false },
"2.5.29.56": { "d": "noRevAvail", "c": "X.509 extension", "w": false },
"2.5.29.57": { "d": "acceptablePrivilegePolicies", "c": "X.509 extension", "w": false },
"2.5.29.58": { "d": "toBeRevoked", "c": "X.509 extension", "w": false },
"2.5.29.59": { "d": "revokedGroups", "c": "X.509 extension", "w": false },
"2.5.29.60": { "d": "expiredCertsOnCRL", "c": "X.509 extension", "w": false },
"2.5.29.61": { "d": "indirectIssuer", "c": "X.509 extension", "w": false },
"2.5.29.62": { "d": "noAssertion", "c": "X.509 extension", "w": false },
"2.5.29.63": { "d": "aAissuingDistributionPoint", "c": "X.509 extension", "w": false },
"2.5.29.64": { "d": "issuedOnBehalfOf", "c": "X.509 extension", "w": false },
"2.5.29.65": { "d": "singleUse", "c": "X.509 extension", "w": false },
"2.5.29.66": { "d": "groupAC", "c": "X.509 extension", "w": false },
"2.5.29.67": { "d": "allowedAttAss", "c": "X.509 extension", "w": false },
"2.5.29.68": { "d": "attributeMappings", "c": "X.509 extension", "w": false },
"2.5.29.69": { "d": "holderNameConstraints", "c": "X.509 extension", "w": false },
"2.16.724.1.2.2.4.1": { "d": "personalDataInfo", "c": "Spanish Government PKI?", "w": false },
"2.16.840.1.101.2.1.1.1": { "d": "sdnsSignatureAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.2": { "d": "fortezzaSignatureAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicSignatureAlgorithm, this OID is better known as dsaWithSHA-1.", "w": false },
"2.16.840.1.101.2.1.1.3": { "d": "sdnsConfidentialityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.4": { "d": "fortezzaConfidentialityAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicConfidentialityAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.5": { "d": "sdnsIntegrityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.6": { "d": "fortezzaIntegrityAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicIntegrityAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.7": { "d": "sdnsTokenProtectionAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.8": { "d": "fortezzaTokenProtectionAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly know as mosaicTokenProtectionAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.9": { "d": "sdnsKeyManagementAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.10": { "d": "fortezzaKeyManagementAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKeyManagementAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.11": { "d": "sdnsKMandSigAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.12": { "d": "fortezzaKMandSigAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKMandSigAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.13": { "d": "suiteASignatureAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.14": { "d": "suiteAConfidentialityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.15": { "d": "suiteAIntegrityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.16": { "d": "suiteATokenProtectionAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.17": { "d": "suiteAKeyManagementAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.18": { "d": "suiteAKMandSigAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.19": { "d": "fortezzaUpdatedSigAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicUpdatedSigAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.20": { "d": "fortezzaKMandUpdSigAlgorithms", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKMandUpdSigAlgorithms", "w": false },
"2.16.840.1.101.2.1.1.21": { "d": "fortezzaUpdatedIntegAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicUpdatedIntegAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.22": { "d": "keyExchangeAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKeyEncryptionAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.23": { "d": "fortezzaWrap80Algorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.24": { "d": "kEAKeyEncryptionAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.2.1": { "d": "rfc822MessageFormat", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.2": { "d": "emptyContent", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.3": { "d": "cspContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.42": { "d": "mspRev3ContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.48": { "d": "mspContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.49": { "d": "mspRekeyAgentProtocol", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.50": { "d": "mspMMP", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.66": { "d": "mspRev3-1ContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.72": { "d": "forwardedMSPMessageBodyPart", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.73": { "d": "mspForwardedMessageParameters", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.74": { "d": "forwardedCSPMsgBodyPart", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.75": { "d": "cspForwardedMessageParameters", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.76": { "d": "mspMMP2", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.3.1": { "d": "sdnsSecurityPolicy", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.2": { "d": "sdnsPRBAC", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.3": { "d": "mosaicPRBAC", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.10": { "d": "siSecurityPolicy", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.10.0": { "d": "siNASP", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.1": { "d": "siELCO", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.2": { "d": "siTK", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.3": { "d": "siDSAP", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.4": { "d": "siSSSS", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.5": { "d": "siDNASP", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.6": { "d": "siBYEMAN", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.7": { "d": "siREL-US", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.8": { "d": "siREL-AUS", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.9": { "d": "siREL-CAN", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.10": { "d": "siREL_UK", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.11": { "d": "siREL-NZ", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.12": { "d": "siGeneric", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11": { "d": "genser", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.11.0": { "d": "genserNations", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11.1": { "d": "genserComsec", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11.2": { "d": "genserAcquisition", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11.3": { "d": "genserSecurityCategories", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.11.3.0": { "d": "genserTagSetName", "c": "SDN.700 INFOSEC GENSER policy", "w": false },
"2.16.840.1.101.2.1.3.12": { "d": "defaultSecurityPolicy", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.13": { "d": "capcoMarkings", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.13.0": { "d": "capcoSecurityCategories", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.1": { "d": "capcoTagSetName1", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.2": { "d": "capcoTagSetName2", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.3": { "d": "capcoTagSetName3", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.4": { "d": "capcoTagSetName4", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.5.1": { "d": "sdnsKeyManagementCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.2": { "d": "sdnsUserSignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.3": { "d": "sdnsKMandSigCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.4": { "d": "fortezzaKeyManagementCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.5": { "d": "fortezzaKMandSigCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.6": { "d": "fortezzaUserSignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.7": { "d": "fortezzaCASignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.8": { "d": "sdnsCASignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.10": { "d": "auxiliaryVector", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.11": { "d": "mlReceiptPolicy", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.12": { "d": "mlMembership", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.13": { "d": "mlAdministrators", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.14": { "d": "alid", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.20": { "d": "janUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.21": { "d": "febUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.22": { "d": "marUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.23": { "d": "aprUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.24": { "d": "mayUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.25": { "d": "junUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.26": { "d": "julUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.27": { "d": "augUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.28": { "d": "sepUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.29": { "d": "octUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.30": { "d": "novUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.31": { "d": "decUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.40": { "d": "metaSDNSckl", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.41": { "d": "sdnsCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.42": { "d": "metaSDNSsignatureCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.43": { "d": "sdnsSignatureCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.44": { "d": "sdnsCertificateRevocationList", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.45": { "d": "fortezzaCertificateRevocationList", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.46": { "d": "fortezzaCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.47": { "d": "alExemptedAddressProcessor", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.48": { "d": "guard", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.49": { "d": "algorithmsSupported", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.50": { "d": "suiteAKeyManagementCertificate", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.51": { "d": "suiteAKMandSigCertificate", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.52": { "d": "suiteAUserSignatureCertificate", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.53": { "d": "prbacInfo", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.54": { "d": "prbacCAConstraints", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.55": { "d": "sigOrKMPrivileges", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.56": { "d": "commPrivileges", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.57": { "d": "labeledAttribute", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.58": { "d": "policyInformationFile", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.59": { "d": "secPolicyInformationFile", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.60": { "d": "cAClearanceConstraint", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.7.1": { "d": "cspExtns", "c": "SDN.700 INFOSEC extensions", "w": false },
"2.16.840.1.101.2.1.7.1.0": { "d": "cspCsExtn", "c": "SDN.700 INFOSEC extensions", "w": false },
"2.16.840.1.101.2.1.8.1": { "d": "mISSISecurityCategories", "c": "SDN.700 INFOSEC security category", "w": false },
"2.16.840.1.101.2.1.8.2": { "d": "standardSecurityLabelPrivileges", "c": "SDN.700 INFOSEC security category", "w": false },
"2.16.840.1.101.2.1.10.1": { "d": "sigPrivileges", "c": "SDN.700 INFOSEC privileges", "w": false },
"2.16.840.1.101.2.1.10.2": { "d": "kmPrivileges", "c": "SDN.700 INFOSEC privileges", "w": false },
"2.16.840.1.101.2.1.10.3": { "d": "namedTagSetPrivilege", "c": "SDN.700 INFOSEC privileges", "w": false },
"2.16.840.1.101.2.1.11.1": { "d": "ukDemo", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.2": { "d": "usDODClass2", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.3": { "d": "usMediumPilot", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.4": { "d": "usDODClass4", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.5": { "d": "usDODClass3", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.6": { "d": "usDODClass5", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.12.0": { "d": "testSecurityPolicy", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1": { "d": "tsp1", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0": { "d": "tsp1SecurityCategories", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0.0": { "d": "tsp1TagSetZero", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0.1": { "d": "tsp1TagSetOne", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0.2": { "d": "tsp1TagSetTwo", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2": { "d": "tsp2", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0": { "d": "tsp2SecurityCategories", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0.0": { "d": "tsp2TagSetZero", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0.1": { "d": "tsp2TagSetOne", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0.2": { "d": "tsp2TagSetTwo", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3": { "d": "kafka", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0": { "d": "kafkaSecurityCategories", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0.1": { "d": "kafkaTagSetName1", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0.2": { "d": "kafkaTagSetName2", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0.3": { "d": "kafkaTagSetName3", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.1.1": { "d": "tcp1", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.3.1": { "d": "slabel", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.2": { "d": "pki", "c": "NIST", "w": true },
"2.16.840.1.101.3.2.1": { "d": "NIST policyIdentifier", "c": "NIST policies", "w": true },
"2.16.840.1.101.3.2.1.3.1": { "d": "fbcaRudimentaryPolicy", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.3.2": { "d": "fbcaBasicPolicy", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.3.3": { "d": "fbcaMediumPolicy", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.3.4": { "d": "fbcaHighPolicy", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.48.1": { "d": "nistTestPolicy1", "c": "NIST PKITS policies", "w": false },
"2.16.840.1.101.3.2.1.48.2": { "d": "nistTestPolicy2", "c": "NIST PKITS policies", "w": false },
"2.16.840.1.101.3.2.1.48.3": { "d": "nistTestPolicy3", "c": "NIST PKITS policies", "w": false },
"2.16.840.1.101.3.2.1.48.4": { "d": "nistTestPolicy4", "c": "NIST PKITS policies", "w": false },
"2.16.840.1.101.3.2.1.48.5": { "d": "nistTestPolicy5", "c": "NIST PKITS policies", "w": false },
"2.16.840.1.101.3.2.1.48.6": { "d": "nistTestPolicy6", "c": "NIST PKITS policies", "w": false },
"2.16.840.1.101.3.2.2": { "d": "gak", "c": "CSOR GAK extended key usage", "w": true },
"2.16.840.1.101.3.2.2.1": { "d": "kRAKey", "c": "CSOR GAK extended key usage", "w": true },
"2.16.840.1.101.3.2.3": { "d": "extensions", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.3.1": { "d": "kRTechnique", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.3.2": { "d": "kRecoveryCapable", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.3.3": { "d": "kR", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.4": { "d": "keyRecoverySchemes", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.2.5": { "d": "krapola", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.3": { "d": "arpa", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.4": { "d": "nistAlgorithm", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1": { "d": "aes", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.1": { "d": "aes128-ECB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.2": { "d": "aes128-CBC", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.3": { "d": "aes128-OFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.4": { "d": "aes128-CFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.5": { "d": "aes128-wrap", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.6": { "d": "aes128-GCM", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.7": { "d": "aes128-CCM", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.8": { "d": "aes128-wrap-pad", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.21": { "d": "aes192-ECB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.22": { "d": "aes192-CBC", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.23": { "d": "aes192-OFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.24": { "d": "aes192-CFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.25": { "d": "aes192-wrap", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.26": { "d": "aes192-GCM", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.27": { "d": "aes192-CCM", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.28": { "d": "aes192-wrap-pad", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.41": { "d": "aes256-ECB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.42": { "d": "aes256-CBC", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.43": { "d": "aes256-OFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.44": { "d": "aes256-CFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.45": { "d": "aes256-wrap", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.46": { "d": "aes256-GCM", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.47": { "d": "aes256-CCM", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.48": { "d": "aes256-wrap-pad", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2": { "d": "hashAlgos", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.1": { "d": "sha256", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.2": { "d": "sha384", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.3": { "d": "sha512", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.4": { "d": "sha224", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.3.1": { "d": "dsaWithSha224", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.3.2": { "d": "dsaWithSha256", "c": "NIST Algorithm", "w": false },
"2.16.840.1.113719.1.2.8": { "d": "novellAlgorithm", "c": "Novell", "w": false },
"2.16.840.1.113719.1.2.8.22": { "d": "desCbcIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.23": { "d": "desCbcPadIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.24": { "d": "desEDE2CbcIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.25": { "d": "desEDE2CbcPadIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.26": { "d": "desEDE3CbcIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.27": { "d": "desEDE3CbcPadIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.28": { "d": "rc5CbcPad", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.29": { "d": "md2WithRSAEncryptionBSafe1", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.30": { "d": "md5WithRSAEncryptionBSafe1", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.31": { "d": "sha1WithRSAEncryptionBSafe1", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.32": { "d": "lmDigest", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.40": { "d": "md2", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.50": { "d": "md5", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.51": { "d": "ikeHmacWithSHA1-RSA", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.52": { "d": "ikeHmacWithMD5-RSA", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.69": { "d": "rc2CbcPad", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.82": { "d": "sha-1", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.92": { "d": "rc2BSafe1Cbc", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.95": { "d": "md4", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.130": { "d": "md4Packet", "c": "Novell keyed hash", "w": false },
"2.16.840.1.113719.1.2.8.131": { "d": "rsaEncryptionBsafe1", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.132": { "d": "nwPassword", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.133": { "d": "novellObfuscate-1", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.9": { "d": "pki", "c": "Novell", "w": false },
"2.16.840.1.113719.1.9.4": { "d": "pkiAttributeType", "c": "Novell PKI", "w": false },
"2.16.840.1.113719.1.9.4.1": { "d": "securityAttributes", "c": "Novell PKI attribute type", "w": false },
"2.16.840.1.113719.1.9.4.2": { "d": "relianceLimit", "c": "Novell PKI attribute type", "w": false },
"2.16.840.1.113730.1": { "d": "cert-extension", "c": "Netscape", "w": false },
"2.16.840.1.113730.1.1": { "d": "netscape-cert-type", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.2": { "d": "netscape-base-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.3": { "d": "netscape-revocation-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.4": { "d": "netscape-ca-revocation-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.7": { "d": "netscape-cert-renewal-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.8": { "d": "netscape-ca-policy-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.9": { "d": "HomePage-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.10": { "d": "EntityLogo", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.11": { "d": "UserPicture", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.12": { "d": "netscape-ssl-server-name", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.13": { "d": "netscape-comment", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.2": { "d": "data-type", "c": "Netscape", "w": false },
"2.16.840.1.113730.2.1": { "d": "dataGIF", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.2": { "d": "dataJPEG", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.3": { "d": "dataURL", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.4": { "d": "dataHTML", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.5": { "d": "certSequence", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.6": { "d": "certURL", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.3": { "d": "directory", "c": "Netscape", "w": false },
"2.16.840.1.113730.3.1": { "d": "ldapDefinitions", "c": "Netscape directory", "w": false },
"2.16.840.1.113730.3.1.1": { "d": "carLicense", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.1.2": { "d": "departmentNumber", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.1.3": { "d": "employeeNumber", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.1.4": { "d": "employeeType", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.2.2": { "d": "inetOrgPerson", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.4.1": { "d": "serverGatedCrypto", "c": "Netscape", "w": false },
"2.16.840.1.113733.1.6.3": { "d": "verisignCZAG", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.6": { "d": "verisignInBox", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.11": { "d": "verisignOnsiteJurisdictionHash", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.13": { "d": "Unknown Verisign VPN extension", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.15": { "d": "verisignServerID", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.7.1.1": { "d": "verisignCertPolicies95Qualifier1", "c": "Verisign policy", "w": false },
"2.16.840.1.113733.1.7.1.1.1": { "d": "verisignCPSv1notice", "c": "Verisign policy (obsolete)", "w": false },
"2.16.840.1.113733.1.7.1.1.2": { "d": "verisignCPSv1nsi", "c": "Verisign policy (obsolete)", "w": false },
"2.16.840.1.113733.1.8.1": { "d": "verisignISSStrongCrypto", "c": "Verisign", "w": false },
"2.16.840.1.113733.1": { "d": "pki", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.9": { "d": "pkcs7Attribute", "c": "Verisign PKI extension", "w": false },
"2.16.840.1.113733.1.9.2": { "d": "messageType", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.3": { "d": "pkiStatus", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.4": { "d": "failInfo", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.5": { "d": "senderNonce", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.6": { "d": "recipientNonce", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.7": { "d": "transID", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.8": { "d": "extensionReq", "c": "Verisign PKCS #7 attribute.  Use PKCS #9 extensionRequest instead", "w": true },
"2.16.840.1.113741.2": { "d": "intelCDSA", "c": "Intel CDSA", "w": false },
"2.16.840.1.114412.1": { "d": "digiCertNonEVCerts", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.1": { "d": "digiCertOVCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.2": { "d": "digiCertDVCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.11": { "d": "digiCertFederatedDeviceCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.3.0.1": { "d": "digiCertGlobalCAPolicy", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.3.0.2": { "d": "digiCertHighAssuranceEVCAPolicy", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.3.0.3": { "d": "digiCertGlobalRootCAPolicy", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.1.3.0.4": { "d": "digiCertAssuredIDRootCAPolicy", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.2": { "d": "digiCertEVCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.3": { "d": "digiCertObjectSigningCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.3.1": { "d": "digiCertCodeSigningCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.3.2": { "d": "digiCertEVCodeSigningCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.3.11": { "d": "digiCertKernelCodeSigningCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.3.21": { "d": "digiCertDocumentSigningCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4": { "d": "digiCertClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.1.1": { "d": "digiCertLevel1PersonalClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.1.2": { "d": "digiCertLevel1EnterpriseClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.2": { "d": "digiCertLevel2ClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.3.1": { "d": "digiCertLevel3USClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.3.2": { "d": "digiCertLevel3CBPClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.4.1": { "d": "digiCertLevel4USClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.4.2": { "d": "digiCertLevel4CBPClientCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.5.1": { "d": "digiCertPIVHardwareCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.5.2": { "d": "digiCertPIVCardAuthCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.2.4.5.3": { "d": "digiCertPIVContentSigningCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.4.31": { "d": "digiCertGridClassicCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.4.31.5": { "d": "digiCertGridIntegratedCert", "c": "Digicert CA policy", "w": false },
"2.16.840.1.114412.31.4.31.1": { "d": "digiCertGridHostCert", "c": "Digicert CA policy", "w": false },
"2.23.42.0": { "d": "contentType", "c": "SET", "w": false },
"2.23.42.0.0": { "d": "panData", "c": "SET contentType", "w": false },
"2.23.42.0.1": { "d": "panToken", "c": "SET contentType", "w": false },
"2.23.42.0.2": { "d": "panOnly", "c": "SET contentType", "w": false },
"2.23.42.1": { "d": "msgExt", "c": "SET", "w": false },
"2.23.42.2": { "d": "field", "c": "SET", "w": false },
"2.23.42.2.0": { "d": "fullName", "c": "SET field", "w": false },
"2.23.42.2.1": { "d": "givenName", "c": "SET field", "w": false },
"2.23.42.2.2": { "d": "familyName", "c": "SET field", "w": false },
"2.23.42.2.3": { "d": "birthFamilyName", "c": "SET field", "w": false },
"2.23.42.2.4": { "d": "placeName", "c": "SET field", "w": false },
"2.23.42.2.5": { "d": "identificationNumber", "c": "SET field", "w": false },
"2.23.42.2.6": { "d": "month", "c": "SET field", "w": false },
"2.23.42.2.7": { "d": "date", "c": "SET field", "w": false },
"2.23.42.2.8": { "d": "address", "c": "SET field", "w": false },
"2.23.42.2.9": { "d": "telephone", "c": "SET field", "w": false },
"2.23.42.2.10": { "d": "amount", "c": "SET field", "w": false },
"2.23.42.2.11": { "d": "accountNumber", "c": "SET field", "w": false },
"2.23.42.2.12": { "d": "passPhrase", "c": "SET field", "w": false },
"2.23.42.3": { "d": "attribute", "c": "SET", "w": false },
"2.23.42.3.0": { "d": "cert", "c": "SET attribute", "w": false },
"2.23.42.3.0.0": { "d": "rootKeyThumb", "c": "SET cert attribute", "w": false },
"2.23.42.3.0.1": { "d": "additionalPolicy", "c": "SET cert attribute", "w": false },
"2.23.42.4": { "d": "algorithm", "c": "SET", "w": false },
"2.23.42.5": { "d": "policy", "c": "SET", "w": false },
"2.23.42.5.0": { "d": "root", "c": "SET policy", "w": false },
"2.23.42.6": { "d": "module", "c": "SET", "w": false },
"2.23.42.7": { "d": "certExt", "c": "SET", "w": false },
"2.23.42.7.0": { "d": "hashedRootKey", "c": "SET cert extension", "w": false },
"2.23.42.7.1": { "d": "certificateType", "c": "SET cert extension", "w": false },
"2.23.42.7.2": { "d": "merchantData", "c": "SET cert extension", "w": false },
"2.23.42.7.3": { "d": "cardCertRequired", "c": "SET cert extension", "w": false },
"2.23.42.7.4": { "d": "tunneling", "c": "SET cert extension", "w": false },
"2.23.42.7.5": { "d": "setExtensions", "c": "SET cert extension", "w": false },
"2.23.42.7.6": { "d": "setQualifier", "c": "SET cert extension", "w": false },
"2.23.42.8": { "d": "brand", "c": "SET", "w": false },
"2.23.42.8.1": { "d": "IATA-ATA", "c": "SET brand", "w": false },
"2.23.42.8.4": { "d": "VISA", "c": "SET brand", "w": false },
"2.23.42.8.5": { "d": "MasterCard", "c": "SET brand", "w": false },
"2.23.42.8.30": { "d": "Diners", "c": "SET brand", "w": false },
"2.23.42.8.34": { "d": "AmericanExpress", "c": "SET brand", "w": false },
"2.23.42.8.6011": { "d": "Novus", "c": "SET brand", "w": false },
"2.23.42.9": { "d": "vendor", "c": "SET", "w": false },
"2.23.42.9.0": { "d": "GlobeSet", "c": "SET vendor", "w": false },
"2.23.42.9.1": { "d": "IBM", "c": "SET vendor", "w": false },
"2.23.42.9.2": { "d": "CyberCash", "c": "SET vendor", "w": false },
"2.23.42.9.3": { "d": "Terisa", "c": "SET vendor", "w": false },
"2.23.42.9.4": { "d": "RSADSI", "c": "SET vendor", "w": false },
"2.23.42.9.5": { "d": "VeriFone", "c": "SET vendor", "w": false },
"2.23.42.9.6": { "d": "TrinTech", "c": "SET vendor", "w": false },
"2.23.42.9.7": { "d": "BankGate", "c": "SET vendor", "w": false },
"2.23.42.9.8": { "d": "GTE", "c": "SET vendor", "w": false },
"2.23.42.9.9": { "d": "CompuSource", "c": "SET vendor", "w": false },
"2.23.42.9.10": { "d": "Griffin", "c": "SET vendor", "w": false },
"2.23.42.9.11": { "d": "Certicom", "c": "SET vendor", "w": false },
"2.23.42.9.12": { "d": "OSS", "c": "SET vendor", "w": false },
"2.23.42.9.13": { "d": "TenthMountain", "c": "SET vendor", "w": false },
"2.23.42.9.14": { "d": "Antares", "c": "SET vendor", "w": false },
"2.23.42.9.15": { "d": "ECC", "c": "SET vendor", "w": false },
"2.23.42.9.16": { "d": "Maithean", "c": "SET vendor", "w": false },
"2.23.42.9.17": { "d": "Netscape", "c": "SET vendor", "w": false },
"2.23.42.9.18": { "d": "Verisign", "c": "SET vendor", "w": false },
"2.23.42.9.19": { "d": "BlueMoney", "c": "SET vendor", "w": false },
"2.23.42.9.20": { "d": "Lacerte", "c": "SET vendor", "w": false },
"2.23.42.9.21": { "d": "Fujitsu", "c": "SET vendor", "w": false },
"2.23.42.9.22": { "d": "eLab", "c": "SET vendor", "w": false },
"2.23.42.9.23": { "d": "Entrust", "c": "SET vendor", "w": false },
"2.23.42.9.24": { "d": "VIAnet", "c": "SET vendor", "w": false },
"2.23.42.9.25": { "d": "III", "c": "SET vendor", "w": false },
"2.23.42.9.26": { "d": "OpenMarket", "c": "SET vendor", "w": false },
"2.23.42.9.27": { "d": "Lexem", "c": "SET vendor", "w": false },
"2.23.42.9.28": { "d": "Intertrader", "c": "SET vendor", "w": false },
"2.23.42.9.29": { "d": "Persimmon", "c": "SET vendor", "w": false },
"2.23.42.9.30": { "d": "NABLE", "c": "SET vendor", "w": false },
"2.23.42.9.31": { "d": "espace-net", "c": "SET vendor", "w": false },
"2.23.42.9.32": { "d": "Hitachi", "c": "SET vendor", "w": false },
"2.23.42.9.33": { "d": "Microsoft", "c": "SET vendor", "w": false },
"2.23.42.9.34": { "d": "NEC", "c": "SET vendor", "w": false },
"2.23.42.9.35": { "d": "Mitsubishi", "c": "SET vendor", "w": false },
"2.23.42.9.36": { "d": "NCR", "c": "SET vendor", "w": false },
"2.23.42.9.37": { "d": "e-COMM", "c": "SET vendor", "w": false },
"2.23.42.9.38": { "d": "Gemplus", "c": "SET vendor", "w": false },
"2.23.42.10": { "d": "national", "c": "SET", "w": false },
"2.23.42.10.392": { "d": "Japan", "c": "SET national", "w": false },
"2.23.134.1.4.2.1": { "d": "postSignumRootQCA  ", "c": "PostSignum CA", "w": false },
"2.23.134.1.2.2.3": { "d": "postSignumPublicCA ", "c": "PostSignum CA", "w": false },
"2.23.134.1.2.1.8.210": { "d": "postSignumCommercialServerPolicy", "c": "PostSignum CA", "w": false },
"2.23.136.1.1.1": { "d": "mRTDSignatureData", "c": "ICAO MRTD", "w": false },
"2.54.1775.2": { "d": "hashedRootKey", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.3": { "d": "certificateType", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.4": { "d": "merchantData", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.5": { "d": "cardCertRequired", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.6": { "d": "tunneling", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.7": { "d": "setQualifier", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.99": { "d": "setData", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"1.2.40.0.17.1.22": { "d": "A-Trust EV policy", "c": "A-Trust CA Root", "w": false },
"1.3.6.1.4.1.34697.2.1": { "d": "AffirmTrust EV policy", "c": "AffirmTrust Commercial", "w": false },
"1.3.6.1.4.1.34697.2.2": { "d": "AffirmTrust EV policy", "c": "AffirmTrust Networking", "w": false },
"1.3.6.1.4.1.34697.2.3": { "d": "AffirmTrust EV policy", "c": "AffirmTrust Premium", "w": false },
"1.3.6.1.4.1.34697.2.4": { "d": "AffirmTrust EV policy", "c": "AffirmTrust Premium ECC", "w": false },
"2.16.578.1.26.1.3.3": { "d": "BuyPass EV policy", "c": "BuyPass Class 3 EV", "w": false },
"1.3.6.1.4.1.17326.10.14.2.1.2": { "d": "Camerfirma EV policy", "c": "Camerfirma CA Root", "w": false },
"1.3.6.1.4.1.17326.10.8.12.1.2": { "d": "Camerfirma EV policy", "c": "Camerfirma CA Root", "w": false },
"1.3.6.1.4.1.22234.2.5.2.3.1": { "d": "CertPlus EV policy", "c": "CertPlus Class 2 Primary CA (formerly Keynectis)", "w": false },
"1.3.6.1.4.1.6449.1.2.1.5.1": { "d": "Comodo EV policy", "c": "COMODO Certification Authority", "w": false },
"1.3.6.1.4.1.6334.1.100.1": { "d": "Cybertrust EV policy", "c": "Cybertrust Global Root (now Verizon Business)", "w": false },
"1.3.6.1.4.1.4788.2.202.1": { "d": "D-TRUST EV policy", "c": "D-TRUST Root Class 3 CA 2 EV 2009", "w": false },
"2.16.840.1.114412.2.1": { "d": "DigiCert EV policy", "c": "DigiCert High Assurance EV Root CA", "w": false },
"2.16.528.1.1001.1.1.1.12.6.1.1.1": { "d": "DigiNotar EV policy", "c": "DigiNotar Root CA", "w": false },
"2.16.840.1.114028.10.1.2": { "d": "Entrust EV policy", "c": "Entrust Root Certification Authority", "w": false },
"1.3.6.1.4.1.14370.1.6": { "d": "GeoTrust EV policy", "c": "GeoTrust Primary Certification Authority (formerly Equifax)", "w": false },
"1.3.6.1.4.1.4146.1.1": { "d": "GlobalSign EV policy", "c": "GlobalSign", "w": false },
"2.16.840.1.114413.1.7.23.3": { "d": "GoDaddy EV policy", "c": "GoDaddy Class 2 Certification Authority (formerly ValiCert)", "w": false },
"1.3.6.1.4.1.14777.6.1.1": { "d": "Izenpe EV policy", "c": "Certificado de Servidor Seguro SSL EV", "w": false },
"1.3.6.1.4.1.14777.6.1.2": { "d": "Izenpe EV policy", "c": "Certificado de Sede Electronica EV", "w": false },
"1.3.6.1.4.1.782.1.2.1.8.1": { "d": "Network Solutions EV policy", "c": "Network Solutions Certificate Authority", "w": false },
"1.3.6.1.4.1.8024.0.2.100.1.2": { "d": "QuoVadis EV policy", "c": "QuoVadis Root CA 2", "w": false },
"1.2.392.200091.100.721.1": { "d": "Security Communication (SECOM) EV policy", "c": "Security Communication RootCA1", "w": false },
"2.16.840.1.114414.1.7.23.3": { "d": "Starfield EV policy", "c": "Starfield Class 2 Certification Authority", "w": false },
"1.3.6.1.4.1.23223.1.1.1": { "d": "StartCom EV policy", "c": "StartCom Certification Authority", "w": false },
"2.16.756.1.89.1.2.1.1": { "d": "SwissSign EV policy", "c": "SwissSign Gold CA - G2", "w": false },
"1.3.6.1.4.1.7879.13.24.1": { "d": "T-TeleSec EV policy", "c": "T-TeleSec GlobalRoot Class 3", "w": false },
"2.16.840.1.113733.1.7.48.1": { "d": "Thawte EV policy", "c": "Thawte Premium Server CA", "w": false },
"2.16.840.1.114404.1.1.2.4.1": { "d": "TrustWave EV policy", "c": "TrustWave CA, formerly SecureTrust, before that XRamp", "w": false },
"1.3.6.1.4.1.40869.1.1.22.3": { "d": "TWCA EV policy", "c": "TWCA Root Certification Authority", "w": false },
"2.16.840.1.113733.1.7.23.6": { "d": "VeriSign EV policy", "c": "VeriSign Class 3 Public Primary Certification Authority", "w": false },
"2.16.840.1.114171.500.9": { "d": "Wells Fargo EV policy", "c": "Wells Fargo WellsSecure Public Root Certificate Authority", "w": false },
"END": ""
};
function PKCS7() {
    var obj, oid;
    this.__proto__ = {
        set OID(v) {
            if (trusted.isString(v))
                v = new trusted.PKI.OID(v);
            if (oid === undefined || v.value !== oid.value) {
                oid = v;
            }
        },
        get OID() {
            if (oid === undefined && obj!==undefined) {
                oid = new trusted.PKI.OID(obj.contentType);
            }
            return oid;
        },
        get content() {
            if (obj === undefined)
                return null;
            return obj.content;
        }
    };

    this.__proto__.toObject = function() {
        var o = {
            contentType: this.OID.value
        };
        if (this.content!==null)
            o.content = this.content;
        return o;
    };

    function init(v) {
        if (v === undefined)
            return;
        if (trusted.isString(v)) {
            if (v in trusted.PKI.PKCS7Types) {
                oid = new trusted.PKI.OID(trusted.PKI.PKCS7Types[v]);
                return;
            } else {
                v = objFromBuffer(v, "ContentInfo");
            }
        }
        if (!(trusted.isObject(v) && ("contentType" in v && "content" in v)))
            "PKCS7.new: Параметр имеет не верный формат.";
        obj = v;
    }

    init.call(this, arguments[0]);

}
trusted.PKI.PKCS7 = PKCS7;

trusted.PKI.PKCS7Types = {
    "data": "1.2.840.113549.1.7.1",
    "signedData": "1.2.840.113549.1.7.2",
    "envelopedData": "1.2.840.113549.1.7.3",
    "signedAndEnvelopedData": "1.2.840.113549.1.7.4",
    "digestedData": "1.2.840.113549.1.7.5",
    "encryptedData": "1.2.840.113549.1.7.6"
};(function() {

    function Request() {
        var obj;
        var cache;

        this.__proto__ = {
            get TBSRequest() {
                return cache.tbs;
            },
            get version() {
                return obj.certificationRequestInfo.version;
            },
            get subjectName() {
                if (cache.subject === undefined) { //cache
                    cache.subject = new trusted.PKI.Name(obj.certificationRequestInfo.subject);
                }
                return cache.subject;
            },
            get publicKey() {
                if (cache.pk === undefined) {
                    cache.pk = new trusted.PKI.PublicKey(obj.certificationRequestInfo.subjectPKInfo);
                }
                return cache.pk;
            },
            get attributes() {
                if (cache.attrs === undefined) {
                    var attrs = obj.certificationRequestInfo.attributes;
                    cache.attrs = [];
                    for (var i = 0; i < attrs.length; i++)
                        cache.attrs.push(new trusted.PKI.RequestAttribute(attrs[i]));
                }
                return cache.attrs;
            },
            get challengePassword() {
                if (cache.psw === undefined) {
                    cache.psw = null;
                    var attr = this.getAttribute("1.2.840.113549.1.9.7");
                    if (attr !== null) {
                        var asn = new trusted.ASN(attr.values[0]);
                        cache.psw = asn.toObject("ChallengePassword").utf8String;
                    }
                }
                return cache.psw;
            },
            get unstructuredName() {
                if (cache.unstrName === undefined) {
                    cache.unstrName = null;
                    var attr = this.getAttribute("1.2.840.113549.1.9.2");
                    if (attr !== null) {
                        var asn = new trusted.ASN(attr.values[0]);
                        var val = asn.toObject("UnstructuredName");
                        val = val[Object.keys(val)[0]];
                        if (trusted.isObject(val)) {
                            cache.unstrName = val[Object.keys(val)[0]];
                        }
                        else
                            cache.unstrName = val;
                    }
                }
                return cache.unstrName;
            },
            get extensions() {
                if (cache.extns === undefined) {
                    var attr = this.getAttribute("1.3.6.1.4.1.311.2.1.14");
                    cache.extns = null;
                    if (attr !== null) {
                        var asn = new trusted.ASN(attr.values[0]);
                        var extns = asn.toObject("Extensions");
                        cache.extns = [];
                        for (var i = 0; i < extns.length; i++)
                            cache.extns.push(new trusted.PKI.Extension(extns[i]));
                    }
                }
                return cache.extns;
            },
            get signatureAlgorithm() {
                if (cache.salg === undefined) { //cache
                    cache.salg = new trusted.PKI.Algorithm(obj.signatureAlgorithm);
                }
                return cache.salg;
            },
            get signature() {
                return obj.signature;
            }
        };

        this.__proto__.getExtension = function(oid) {
            if (this.extensions !== null)
                return getExtnByOID(this.extensions, oid);
        };

        this.__proto__.getAttribute = function(oid) {
            if (trusted.isString(oid))
                oid = new trusted.PKI.OID(oid);
            for (var i = 0; i < this.attributes.length; i++)
                if (this.attributes[i].OID.value === oid.value)
                    return this.attributes[i];
            return null;
        };

        this.__proto__.toObject = function() {
            var o = {
                certificationRequestInfo: {
                    version: this.version,
                    subject: this.subjectName.toObject(),
                    subjectPKInfo: this.publicKey.toObject()
                },
                signatureAlgorithm: this.signatureAlgorithm.toObject(),
                signature: this.signature
            };
            var arr = [];
            for (var i = 0; i < this.attributes.length; i++)
                arr.push(this.attributes[i].toObject());
            o.certificationRequestInfo.attributes = arr;
            return o;
        };

        // inicialization
        function init(v) {
            if (v === undefined)
                throw "Request.new: Параметр не может быть Undefined";
            var asn = null;
            v = objFromBuffer(v, "CertificationRequest");
            if (!(trusted.isObject(v) && ("certificationRequestInfo" in v && "signatureAlgorithm" in v && "signature" in v)))
                throw "RevokedCertificate.new: Задан неверный параметр.";

            obj = v;
            cache = {};
            if (asn !== null)
                cache.tbs = asn.structure.sub[0].encode();
        }

        init.call(this, arguments[0]);
    }

    function RequestAttribute() {
        var obj;
        var cache;

        this.__proto__ = {
            get OID() {
                if (cache.oid === undefined) {
                    cache.oid = new trusted.PKI.OID(obj.type);
                }
                return cache.oid;
            },
            get values() {
                return obj.values;
            }
        };

        this.__proto__.toObject = function() {
            var o = {
                type: this.OID.value,
                values: this.values
            };
            return o;
        };

        this.__proto__.toString = function() {
            var s = "Attribute (" + this.OID.toString() + "): ";
            for (var i = 0; i < this.values.length; i++) {
                s += Der.toHex(this.values[i]) + ((i < (this.values.length - 1)) ? ";" : "");
            }
            return s;
        };

        // inicialization
        function init(v) {
            if (v === undefined)
                throw "RequestAttribute.new: Параметр не может быть Undefined";
            v = objFromBuffer(v, "Attribute");
            if (!(trusted.isObject(v) && ("type" in v && "values" in v)))
                throw "RequestAttribute.new: Задан неверный параметр.";

            obj = v;
            cache = {};
        }

        init.call(this, arguments[0]);
    }

    // attributes

    // exports
    trusted.PKI.Request = Request;
    trusted.PKI.RequestAttribute = RequestAttribute;
})();


function Store(){
    var _items=[];
    
    this.__proto__={
        get items(){
            return _items;
        }
    };
    
    /**
     * Открывает хранилище в памяти
     * @returns {undefined}
     */
    this.__proto__.open=function(){
        
    };
    
    this.__proto__.add = function(item){
      //check item  
    };
}

//export
trusted.PKI.Store = Store;(function() {
    /*    
     id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
     
     AuthorityKeyIdentifier ::= SEQUENCE {
     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
     
     KeyIdentifier ::= OCTET STRING
     */

    function AuthorityKeyIdentifier() {
        var obj;
        var authorityCertIssuer;
        var version;

        this.__proto__ = {
            set keyIdentifier(v) {
            },
            get keyIdentifier() {
                return obj.keyIdentifier === undefined ? null : obj.keyIdentifier;
            },
            set issuerName(v) {
            },
            get issuerName() {
                if (authorityCertIssuer === undefined)
                    if (obj.authorityCertIssuer !== undefined)
                        switch (version) {
                            case 1:
                                authorityCertIssuer = new trusted.PKI.GeneralNames(
                                        [{directoryName: {rdnSequence: obj.authorityCertIssuer.rdnSequence}}]
                                        );
                                break;
                            default:
                                authorityCertIssuer = new trusted.PKI.GeneralNames(obj.authorityCertIssuer);
                        }
                    else
                        authorityCertIssuer = null;
                return authorityCertIssuer;
            },
            set serialNumber(v) {
            },
            get serialNumber() {
                return obj.authorityCertSerialNumber === undefined ? null : obj.authorityCertSerialNumber;
            },
            set version(v) {
            },
            get version() {
                return version;
            }
        };

        this.__proto__.toObject = function() {
            var obj = {};
            if (this.issuerName !== null) {
                var aci;
                switch (this.version) {
                    case 1:
                        aci = this.issuerName[0].toObject();
                        break;
                    default:
                        aci = this.issuerName.toObject();
                }
                obj.authorityCertIssuer = aci;
            }
            if (this.serialNumber !== null) {
                obj.authorityCertSerialNumber = this.serialNumber;
            }
            if (this.keyIdentifier !== null) {
                obj.keyIdentifier = this.keyIdentifier;
            }
            return obj;
        };

        function init(v, oid) {
            if (oid === undefined)
                oid = "2.5.29.35";
            var schema;
            switch (oid) {
                case "2.5.29.1":
                    schema = "AuthorityKeyIdentifier1";
                    version = 1;
                    break;
                default:
                    schema = "AuthorityKeyIdentifier2";
                    version = 2;
            }
            if (v === undefined)
                throw "AuthorityKeyIdentifier.new: parameter can not be undefined."
            v = objFromBuffer(v, schema);
            if (!(trusted.isObject(v)) && (("keyIdentifier" in v) || ("authorityCertIssuer" in v) || ("authorityCertSerialNumber" in v)))
                throw "AuthorityKeyIdentifier.new: parameter is not valid."

            //v.keyIdentifier = Der.toHex(v.keyIdentifier);

            obj = v;
        }

        init.call(this, arguments[0], arguments[1]);
    }

    trusted.PKI.AuthorityKeyIdentifier = AuthorityKeyIdentifier;
})();

(function() {

    function BasicConstraints() {
        var obj, cache = {};
        this.__proto__ = {
            set CA(v) {
            },
            get CA() {
                return obj.cA;
            },
            set pathLength(v) {
            },
            get pathLength() {
                if (cache.pl === undefined) {
                    cache.pl = null;
                    if (obj.pathLenConstraint !== undefined)
                        cache.pl = obj.pathLenConstraint;
                }
                return cache.pl;
            }
        };

        this.__proto__.toObject = function() {
            return {cA: this.CA, pathLenConstraint: this.pathLength};
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "BasicConstraints.new: parameter can not be undefined."
            v = objFromBuffer(v, "BasicConstraints");
            if (!trusted.isObject(v) && !("cA" in v))
                throw "BasicConstraints.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.BasicConstraints = BasicConstraints;
})();

(function() {

// <editor-fold defaultstate="collapsed" desc=" CertificatePolicies ">
    function CertificatePolicies() {
        var obj, pis;
        this.__proto__ = {
            set policies(v) {
            },
            get policies() {
                if (pis === undefined) {
                    pis = [];
                    for (var i = 0; i < obj.length; i++)
                        pis.push(new trusted.PKI.PolicyInformation(obj[i]));
                }
                return pis;
            }
        };

        this.__proto__.toObject = function() {
            var o = [];
            for (var i = 0; i < this.policies.length; i++)
                o.push(this.policies[i].toObject());
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "CertificatePolicies.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("CertificatePolicies");
            }
            if (!(trusted.isArray(v) && v.length > 0))
                throw "CertificatePolicies.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.CertificatePolicies = CertificatePolicies;
    // </editor-fold>

    function PolicyInformation() {
        var obj;
        var idf;
        var qlf;

        this.__proto__ = {
            set OID(v) {
            },
            get OID() {
                if (idf === undefined)
                    idf = new trusted.PKI.OID(obj.policyIdentifier);
                return idf;
            },
            set qualifiers(v) {
            },
            get qualifiers() {
                if (qlf === undefined) {
                    if (obj.policyQualifiers !== undefined) {
                        qlf = [];
                        for (var i = 0; i < obj.policyQualifiers.length; i++) {
                            var pq = obj.policyQualifiers[i];
                            qlf.push(new trusted.PKI.QualifierInfo(pq));
                        }
                    } else
                        qlf = null;
                }
                return qlf;
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.policyIdentifier = this.OID.value;
            if (this.qualifiers !== null) {
                o.policyQualifiers = [];
                for (var i = 0; i < this.qualifiers.length; i++)
                    o.policyQualifiers.push(this.qualifiers[i].toObject());
            }
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "PolicyInformation.new: parameter can not be undefined."
            v = objFromBuffer(v, "PolicyInformation");
            if (!(trusted.isObject(v)) && ("policyIdentifier" in v))
                throw "PolicyInformation.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.PolicyInformation = PolicyInformation;

    function QualifierInfo() {
        var obj, pqid, cps, un;

        this.__proto__ = {
            set OID(v) {
            },
            get  OID() {
                if (pqid === undefined) {
                    pqid = new trusted.PKI.OID(obj.policyQualifierId);
                }
                return pqid;
            },
            set CPSPointer(v) {
            },
            get CPSPointer() {
                if (cps === undefined) {
                    cps = null;
                    if (this.OID.value === "1.3.6.1.5.5.7.2.1") {
                        var asn = new trusted.ASN(this.encoded);
                        cps = asn.toObject("CPSuri");
                    }
                }
                return cps;
            },
            set encoded(v) {
            },
            get encoded() {
                if (trusted.isString(obj.qualifier)) {
                    return obj.qualifier;
                }
                return null;
            },
            set organizationName(v) {
            },
            get organizationName() {
                if (getUserNotice.call(this) !== null) {
                    if (un.noticeRef !== undefined) {
                        var key = Object.keys(un.noticeRef.organization);
                        return un.noticeRef.organization[key];
                    }
                }
                return null;
            },
            set noticeNumbers(v) {
            },
            get noticeNumbers() {
                if (getUserNotice.call(this) !== null) {
                    if (un.noticeRef !== undefined) {
                        return un.noticeRef.noticeNumbers;
                    }
                }
                return null;
            },
            set explicitText(v) {
            },
            get explicitText() {
                if (getUserNotice.call(this) !== null) {
                    if (un.explicitText !== undefined) {
                        var key = Object.keys(un.explicitText);
                        return un.explicitText[key];
                    }
                }
                return null;
            }
        };

        function getUserNotice() {
            if (un === undefined) {
                un = null;
                if (this.policyQualifierID.value === "1.3.6.1.5.5.7.2.2") {
                    var asn = new trusted.ASN(this.encoded);
                    un = asn.toObject("UserNotice");
                }
            }
            return un;
        }

        this.__proto__.toObject = function() {
            var o = {};
            switch (this.OID.value) {
                case "1.3.6.1.5.5.7.2.1":
                    o.qualifier = trusted.ASN.fromObject(this.CPSPointer, "CPSuri").encode();
                    break
                case "1.3.6.1.5.5.7.2.2":
                    var o1;
                    if (this.organizationName !== null) {
                        o1.noticeRef = {};
                        o1.noticeRef.organization = {};
                        o1.noticeRef.organization.utf8String = this.organizationName;
                        o1.noticeRef.noticeNumbers = this.noticeNumbers;
                    }
                    if (this.explicitText !== null) {
                        o1.explicitText = {};
                        o1.explicitText.utf8String = this.explicitText;
                    }
                    if (this.encoded === null) {
                        o.qualifier = trusted.ASN.fromObject(o, "UserNotice").encode();
                    }
                    break
                default:
                    o.qualifier = this.encoded;
            }
            o.policyQualifierId = this.OID.value;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "QualifierInfo.new: parameter can not be undefined."
            v = objFromBuffer(v, "PolicyQualifierInfo");
            if (!(trusted.isObject(v) && (("policyQualifierId" in v) && ("qualifier" in v))))
                throw "QualifierInfo.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.QualifierInfo = QualifierInfo;

})();

// <editor-fold defaultstate="collapsed" desc=" ReasonFlags ">
trusted.PKI.ReasonFlags = {
    Unused: 0x01, //(0)
    KeyCompromise: 0x02, //(1)
    CACompromise: 0x04, //(2)
    AffiliationChanged: 0x08, //(3)
    Superseded: 0x10, //(4)
    CessationOfOperation: 0x20, //(5)
    CertificateHold: 0x40, //(6)
    PrivilegeWithdrawn: 0x80, //(7)
    AACompromise: 0x100 //(8)
};
// </editor-fold>

(function() {



    // <editor-fold defaultstate="collapsed" desc=" DistributionPoints ">
    function CRLDistributionPoints() {
        var obj, dps;
        this.__proto__ = {
            set distributionPoints(v) {
            },
            get distributionPoints() {
                if (dps === undefined) {
                    dps = [];
                    for (var i = 0; i < obj.length; i++)
                        dps.push(new trusted.PKI.DistributionPoint(obj[i]));
                }
                return dps;
            }
        };

        this.__proto__.toObject = function() {
            var o = [];
            for (var i = 0; i < this.distributionPoints.length; i++)
                o.push(this.distributionPoints[i].toObject());
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "CRLDistributionPoints.new: parameter can not be undefined."
            v = objFromBuffer(v, "CRLDistributionPoints");
            if (!trusted.isObject(v) && !trusted.isArray(v))
                throw "CRLDistributionPoints.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.CRLDistributionPoints = CRLDistributionPoints;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" DistributionPointName ">
    function DistributionPointName() {
        var obj;
        var fullName;
        var relName;

        this.__proto__ = {
            set fullName(v) {

            },
            get fullName() {
                if (fullName === undefined)
                    if (obj.fullName === null)
                        fullName = null;
                    else
                        fullName = new trusted.PKI.GeneralNames(obj.fullName);
                return fullName;
            },
            set relativeName(v) {

            },
            get relativeName() {
                if (relName === undefined)
                    if (obj.nameRelativeToCRLIssuer === undefined)
                        relName = null;
                    else
                        relName = new trusted.PKI.RDN(obj.nameRelativeToCRLIssuer);
                return relName;
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            if (this.fullName !== null)
                o.fullName = this.fullName.toObject();
            if (this.relativeName !== null)
                o.nameRelativeToCRLIssuer = this.relativeName.toObject();
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "DistributionPointName.new: parameter can not be undefined."
            v = objFromBuffer(v, "DistributionPointName");
            if (!(trusted.isObject(v) && ("fullName" in v || "nameRelativeToCRLIssuer" in v)))
                throw "DistributionPointName.new: parameter is not valid."

            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.DistributionPointName = DistributionPointName;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" DistributionPoint ">
    function DistributionPoint() {
        var obj;
        var crlIssuer;
        var distPoint;
        var r; //reasons

        this.__proto__ = {
            set CRLIssuer(v) {

            },
            get CRLIssuer() {
                if (crlIssuer === undefined)
                    if (obj.cRLIssuer === null)
                        crlIssuer = null;
                    else
                        crlIssuer = new trusted.PKI.GeneralNames(obj.cRLIssuer);
                return crlIssuer;
            },
            set distributionPoint(v) {

            },
            get distributionPoint() {
                if (distPoint === undefined)
                    if (obj.distributionPoint === null)
                        distPoint = null;
                    else
                        distPoint = new trusted.PKI.DistributionPointName(obj.distributionPoint);
                return distPoint;
            },
            set name(v) {
            },
            get name() {
                return this.distributionPoint;
            },
            set reasons(v) {
            },
            get reasons() {
                if (r === undefined) {
                    if (obj.reasons === null)
                        r = null;
                    else {
                        r = obj.reasons.toNumber();
                    }
                }
                return r;
            }
        };
        
        function createIsFunctions(v) {
            var keys = Object.keys(v);
            for (var i = 0; i < keys.length; i++) {
                var index = i; // Создаем копию i, иначе все функции будут использовать i = keys.
                this.__proto__["is" + keys[index]] = new Function("return ((this.reasons&" + v[keys[index]] + ")>0)?true:false;");
            }
        }

        createIsFunctions.call(this, trusted.PKI.ReasonFlags);

        this.__proto__.toObject = function() {
            var o = {};
            if (this.CRLIssuer !== null)
                o.cRLIssuer = this.CRLIssuer.toObject();
            if (this.distributionPoint !== null)
                o.distributionPoint = this.distributionPoint.toObject();
            if (this.reasons !== null)
                o.reasons = new BitString(this.reasons);
            return o;
        };

        this.__proto__.getURL = function() {
            if (this.distributionPoint === null)
                return null;
            if (this.distributionPoint.fullName !== null)
                return this.distributionPoint.fullName.toString();
            return this.CRLIssuer + this.distributionPoint.relativeName;
        };

        function init(v) {
            if (v === undefined)
                throw "DistributionPointName.new: parameter can not be undefined."
            v = objFromBuffer(v, "DistributionPoint");
            if (!trusted.isObject(v) && !("cRLIssuer" in v || "distributionPoint" in v || "reasons" in v))
                throw "DistributionPointName.new: parameter is not valid.";
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.DistributionPoint = DistributionPoint;
    // </editor-fold>
})();

trusted.PKI.CRLReason = {
    Unspecified: 0,
    KeyCompromise: 1,
    CACompromise: 2,
    AffiliationChanged: 3,
    Superseded: 4,
    CessationOfOperation: 5,
    CertificateHold: 6,
    RemoveFromCRL: 8,
    PrivilegeWithdrawn: 9,
    AACompromise: 10
};

(function() {

    function CRLNumber() {
        var obj;

        this.__proto__ = {
            set value(v) {
            },
            get value() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            var o = this.value;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "CRLNumber.new: parameter can not be undefined."
            v = objFromBuffer(v, "CRLNumber");
            if (!(trusted.isNumber(v) || trusted.isString(v)))
                throw "CRLNumber.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    function IssuingDistributionPoint() {
        var obj;
        var cache;

        this.__proto__ = {
            set pointName(v) {
            },
            get pointName() {
                if (cache.pn === undefined) {
                    cache.pn = null;
                    if (obj.distributionPoint !== null) {
                        cache.pn = obj.distributionPoint.fullName;
                    }
                }
                return cache.pn;
            },
            set onlyContainsUserCerts(v) {
            },
            get onlyContainsUserCerts() {
                return obj.onlyContainsUserCerts;
            },
            set onlyContainsCACerts(v) {
            },
            get onlyContainsCACerts() {
                return obj.onlyContainsCACerts;
            },
            set onlySomeReasons(v) {
            },
            get onlySomeReasons() {
                if (cache.rs === undefined) {
                    cache.rs = null;
                    if (obj.onlySomeReasons !== null)
                        cache.rs = obj.onlySomeReasons.toNumber();
                }
                return cache.rs;
            },
            set indirectCRL(v) {
            },
            get indirectCRL() {
                return obj.indirectCRL;
            },
            set onlyContainsAttributeCerts(v) {
            },
            get onlyContainsAttributeCerts() {
                return obj.onlyContainsAttributeCerts;
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            if (this.pointName !== null)
                o.distributionPoint = {fullName: this.pointName};
            if (this.onlyContainsUserCerts !== null)
                o.onlyContainsUserCerts = this.onlyContainsUserCerts;
            if (this.onlyContainsCACerts !== null)
                o.onlyContainsCACerts = this.onlyContainsCACerts;
            if (this.onlySomeReasons !== null)
                o.onlySomeReasons = new BitString(this.onlyContainsCACerts);
            if (this.indirectCRL !== null)
                o.indirectCRL = this.indirectCRL;
            if (this.onlyContainsAttributeCerts !== null)
                o.onlyContainsAttributeCerts = this.onlyContainsAttributeCerts;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "IssuingDistributionPoint.new: parameter can not be undefined."
            if (trusted.isString(v) && !Hex.test(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("IssuingDistributionPoint");
            }
            if (!(trusted.isObject(v)))
                throw "IssuingDistributionPoint.new: parameter is not valid."

            cache = {};
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    // revoced cert extensions
    //RevocedCode 2.5.29.21
    function ReasonCode() {
        var obj;

        this.__proto__ = {
            set value(v) {
            },
            get value() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            return this.value;
        };

        this.__proto__.toString = function() {
            return ReasonCode.reasonName(this.value);
        };

        function init(v) {
            if (v === undefined)
                throw "ReasonCode.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("ReasonCode");
            }
            if (!(trusted.isNumber(v)))
                throw "ReasonCode.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    ReasonCode.reasonName = function(num){
        if (!trusted.isNumber(num)){
            "ResasonCode.reasonName: Параметр должен быть числом.";
        }
        var keys = Object.keys(trusted.PKI.CRLReason);
            for (var i = 0; i < keys.length; i++) {
                var val = trusted.PKI.CRLReason[keys[i]];
                if (val === num)
                    return keys[i];
            }
            return "Unknown reason";
    };
    
    //InvalidityDate 2.5.29.24
    function InvalidityDate() {
        var obj;

        this.__proto__ = {
            set value(v) {
            },
            get value() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            return this.value;
        };

        this.__proto__.toString = function() {
            return obj.toString();
        };

        function init(v) {
            if (v === undefined)
                throw "InvalidityDate.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("InvalidityDate");
            }
            if (!(trusted.isObject(v)))
                throw "InvalidityDate.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    
    //Certificate Issuer 2.5.29.29

    // exports
    trusted.PKI.CRLNumber = CRLNumber;
    trusted.PKI.BaseCRLNumber = CRLNumber;
    trusted.PKI.IssuingDistributionPoint = IssuingDistributionPoint;
    // revoced cert extensions
    trusted.PKI.ReasonCode = ReasonCode;
    trusted.PKI.InvalidityDate = InvalidityDate;
    trusted.PKI.CertificateIssuer = trusted.PKI.GeneralNames;

})();


(function() {

    function ExtendedKeyUsage() {
        var obj;
        this.__proto__ = {
            set anyExtendedKeyUsage(v) {
            },
            get anyExtendedKeyUsage() {
                return obj;
            },
            set items(v) {
            },
            get items() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            var o = [];
            for (var i = 0; i < this.anyExtendedKeyUsage.length; i++)
                o.push(this.anyExtendedKeyUsage[i].value);
            return o;
        };

        this.__proto__.toString = function() {
            var s = '';
            var l = this.anyExtendedKeyUsage.length;
            for (var i = 0; i < l; i++)
                s += this.anyExtendedKeyUsage[i].toString() + (i !== (l - 1) ? ';' : '');
            return s;
        };

        function init(v) {
            if (v === undefined)
                throw "ExtendedKeyUsage.new: parameter can not be undefined."
            v = objFromBuffer(v, "ExtKeyUsageSyntax");
            if (!(trusted.isObject(v)) && trusted.isArray(v))
                throw "ExtendedKeyUsage.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.length; i++) {
                obj.push(new trusted.PKI.OID(v[i]));
            }
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.ExtendedKeyUsage = ExtendedKeyUsage;
})();


trusted.PKI.FreshestCRL = trusted.PKI.CRLDistributionPoints;



(function() {
    function AccessDescription() {
        var obj;
        var cache = {};

        this.__proto__ = {
            get location() {
                if (cache.l === undefined) {
                    cache.l = new trusted.PKI.GeneralName(obj.accessLocation);
                }
                return cache.l;
            },
            set location(v) {
            },
            get method() {
                if (cache.m === undefined) {
                    cache.m = new trusted.PKI.OID(obj.accessMethod);
                }
                return cache.m;
            },
            set method(v) {
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.accessLocation = this.location.toObject();
            o.accessMethod = this.method.toObject();
            return o;
        };

        //method

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "AccessDescription.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("AccessDescription");
            if (!(trusted.isObject(v) && ("accessLocation" in v && "accessMethod" in v)))
                throw "AccessDescription.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    function InfoAccess() {
        var obj;

        this.__proto__ = {
            get descriptions() {
                return obj;
            },
            set descriptions(v) {
            }
        };

        this.__proto__.toObject = function() {
            var o = [];

            for (var i = 0; i < this.descriptions.length; i++)
                o.push(this.descriptions[i].toObject());

            return o;
        };

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "InfoAccess.new: parameter can not be undefined."
            v = objFromBuffer(v, "AuthorityInfoAccessSyntax");
            if (!trusted.isArray(v))
                throw "AuthorityInfoAccess.new: parameter is not valid."

            obj = [];
            for (var i = 0; i < v.length; i++)
                obj.push(new AccessDescription(v[i]));
        }

        init.call(this, arguments[0]);
    }

    // export
    trusted.PKI.AccessDescription = AccessDescription;
    trusted.PKI.AuthorityInfoAccess = InfoAccess;
    trusted.PKI.SubjectInfoAccess = InfoAccess;
})();


(function() {

    function IssuerAlternativeName() {
        var obj, version, gns;
        this.__proto__ = {
            set generalNames(v) {
            },
            get generalNames() {
                if (gns === undefined) {
                    switch (this.version) {
                        case 1:
                            gns = new trusted.PKI.GeneralNames([{directoryName:obj}]);
                            break;
                        default:
                            gns = new trusted.PKI.GeneralNames(obj);
                    }
                }
                return gns.generalNames;
            },
            set version(v) {
            },
            get version() {
                return version;
            }
        };

        this.__proto__.toString = function() {
            this.generalNames;
            return gns.toString();
        };

        this.__proto__.toObject = function() {
            switch (this.version) {
                case 1:
                    return this.generalNames[0].name.toObject();
                default:
                    this.generalNames;
                    return gns.toObject();
            }
        };

        function init(v, oid) {
            if (oid === undefined)
                oid = "2.5.29.18";
            var schema;
            switch (oid) {
                case "2.5.29.8":
                    schema = "IssuerAlternativeName1";
                    version = 1;
                    break;
                default:
                    schema = "IssuerAlternativeName2";
                    version = 2;
            }
            // Проверка аргумента
            if (v === undefined)
                throw "IssuerName.new: parameter can not be undefined."
            v = objFromBuffer(v, schema);
            if (!trusted.isObject(v) && !trusted.isArray(v))
                throw "IssuerAlternativeName.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0], arguments[1]);
    }

    trusted.PKI.IssuerAlternativeName = IssuerAlternativeName;
})();

(function() {
    function IssuerSignTool() {
        var obj;

        this.__proto__ = {
            set signTool(v) {
            },
            get signTool() {
                return obj.signTool;
            },
            set CATool(v) {
            },
            get CATool() {
                return obj.cATool;
            },
            set signToolCert(v) {
            },
            get signToolCert() {
                return obj.signToolCert;
            },
            set CAToolCert(v) {
            },
            get CAToolCert() {
                return obj.cAToolCert;
            }
        };

        this.__proto__.toObject = function() {
            var obj = {
                cAToolCert: this.CAToolCert,
                signToolCert: this.signToolCert,
                cATool: this.CATool,
                signTool: this.signTool
            };
            return obj;
        };

        this.__proto__.toString = function() {
            var s = 'Extension SubjectSignTool(1.2.643.100.111):';
            s += 'CAToolCert=' + this.CAToolCert + ';';
            s += 'signToolCert=' + this.signToolCert + ';';
            s += 'CATool=' + this.CATool + ';';
            s += 'signTool=' + this.signTool;
            return s;
        };

        function init(v) {
            if (v === undefined) {
                throw "IssuerSignTool.new: parameter can not be undefined."
            }
            v = objFromBuffer(v, "IssuerSignTool");
            if (!(trusted.isObject(v) && (("signTool" in v) || ("cATool" in v) ||
                    ("signToolCert" in v) || ("cAToolCert" in v))))
                throw "IssuerSignTool.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.IssuerSignTool = IssuerSignTool;
})();trusted.PKI.KeyUsageFlags = {
    DigitalSignature: 0x01,
    NonRepudiation: 0x02,
    KeyEncipherment: 0x04,
    DataEncipherment: 0x08,
    KeyAgreement: 0x10,
    KeyCertSign: 0x20,
    CRLSign: 0x40,
    EncipherOnly: 0x80,
    DecipherOnly: 0x100
};

(function() {

    function KeyUsage() {
        var obj, ku;
        this.__proto__ = {
            set keyUsage(v) {
            },
            get keyUsage() {
                if (ku === undefined) {
                    ku = obj.toNumber();
                }
                return ku;
            },
            set value(v){},
            get value(){
                return this.keyUsage;
            }
        };
        
        this.__proto__.toObject = function(){
            return {keuUsage:new BitString(this.keyUsage)};
        };

        function createIsFunctions(v) {
            var keys = Object.keys(v);
            for (var i = 0; i < keys.length; i++) {
                var index = i; // Создаем копию i, иначе все функции будут использовать i = keys.
                this.__proto__["is" + keys[index]] = new Function("return ((this.keyUsage&" + v[keys[index]] + ")>0)?true:false;");
            }
        }

        createIsFunctions.call(this, trusted.PKI.KeyUsageFlags);

        this.__proto__.toObject = function() {
            return new BitString(this.keyUsage);
        };

        function init(v) {
            if (v === undefined)
                throw "KeyUsage.new: parameter can not be undefined."
            if (typeof (v) === "number") {
                obj = new BitString(v);
                return;
            }
            v = objFromBuffer(v, "KeyUsage");
            if (!(trusted.isObject(v) &&
                    v.__proto__.hasOwnProperty("unusedBit") &&
                    v.__proto__.hasOwnProperty("encoded")))
                throw "KeyUsage.new: parameter is not valid."

            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.KeyUsage = KeyUsage;
})();

(function() {
    function PrivateKeyUsagePeriod() {
        var obj;

        //location
        Object.defineProperty(this.__proto__, "notBefore", {
            get: function() {
                if (obj.notBefore === undefined)
                    return null;
                return obj.notBefore;
            },
            set: function(v) {
            },
            enumerable: true,
            configurable: true
        });
        //  method
        Object.defineProperty(this.__proto__, "notAfter", {
            get: function() {
                if (obj.notAfter === undefined)
                    return null;
                return obj.notAfter;
            },
            set: function(v) {
            },
            enumerable: true,
            configurable: true
        });

        this.__proto__.toObject = function() {
            var o = {};
            
            void this.notBefore!==null?o.notBefore=this.notBefore:null;
            void this.notAfter!==null?o.notAfter=this.notAfter:null;
            return o;
        };

        //method

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "PrivateKeyUsagePeriod.new: parameter can not be undefined."
            v = objFromBuffer(v, "PrivateKeyUsagePeriod");
            if (!trusted.isObject(v) && !("notBefore" in v && "notAfter" in v))
                throw "PrivateKeyUsagePeriod.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }


    trusted.PKI.PrivateKeyUsagePeriod = PrivateKeyUsagePeriod;
})();



trusted.PKI.SubjectAlternativeName={};
trusted.PKI.SubjectAlternativeName = trusted.PKI.IssuerAlternativeName;



(function() {

    function SubjectKeyIdentifier() {
        var obj;
        this.__proto__ = {
            set keyIdentifier(v) {
            },
            get keyIdentifier() {
                return obj;
            }
        };

        function init(v) {
            if (v === undefined)
                throw "SubjectKeyIdentifier.new: parameter can not be undefined."
            v = objFromBuffer(v, "SubjectKeyIdentifier");

            obj = Der.toHex(v);
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.SubjectKeyIdentifier = SubjectKeyIdentifier;
})();

(function() {
    function SubjectSignTool() {
        var obj;

        this.__proto__ = {
            set subject(v) {
            },
            get subject() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            return this.subject;
        };

        this.__proto__.toString = function() {
            return 'Extension SubjectSignTool(1.2.643.100.112):' + this.subject;
        };

        /**
         * @param {type} v Parameter
         * @param {type} f DER flas. True is string is DER, else False. Default True
         * @returns {undefined}
         */
        function init(v, f) {
            if (v === undefined) {
                throw "SubjectSignTool.new: parameter can not be undefined."
            }

            if (f === undefined)
                f = true;
            if (f)
                v = objFromBuffer(v, "SubjectSignTool");
            if (!trusted.isString(v))
                throw "SubjectSignTool.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0], arguments[1]);
    }

    trusted.PKI.SubjectSignTool = SubjectSignTool;
})();trusted.schemas.CertificateTrustList = {
    type: "SEQUENCE",
    value: {
        version: {type: "Version", default: 1, index: 0},
        subjectUsage: {type: "SEQUENCE", maxOccurs: trusted.MAX, value: {v: {type: "OBJECT_IDENTIFIER"}}, index:1},
        listIdentifier:{type:"OCTET_STRING",optional:true, index: 2},
        sequenceNumber:{type: "INTEGER", optional:true, index: 3},
        thisUpdate:{type:"Time", index: 4},
        nextUpdate:{type:"Time", optional: true, index: 5},
        subjectAlgorithm:{type:"AlgorithmIdentifier", index: 6},
        subjects:{type:"CTLSubjects", optional: true, index: 7},
        extensions:{type:"Extensions", optional:true, explicit: true, index: 8}
    }
};

trusted.schemas.CTLSubjects= {
    type:"SEQUENCE",
    maxOccurs: trusted.MAX,
    value:{
        v:{
            type:"SEQUENCE",
            value:{
                subjectIdentifier:{type:"OCTET_STRING", index:0},
                attributes:{type:"Attributes", optional: true, index: 1}
            }
        }
    }
};trusted.schemas.CertificationRequest = {
    type: "SEQUENCE",
    value: {
        certificationRequestInfo: {type: "CertificationRequestInfo", index: 0},
        signatureAlgorithm: {type: "AlgorithmIdentifier", index: 1},
        signature: {type: "BIT_STRING", index: 2}
    }
};

trusted.schemas.CertificationRequestInfo = {
    type: "SEQUENCE",
    value: {
        version: {type: "INTEGER", index: 0},
        subject: {type: "Name", index: 1},
        subjectPKInfo: {type: "SubjectPublicKeyInfo", index: 2},
        attributes: {type: "Attributes", context: 0, index: 3}
    }
};

trusted.schemas.Attributes = {
    type: "SET",
    maxOccurs: trusted.MAX,
    value: {
        v: {type: "Attribute"}
    }
};

trusted.schemas.Attribute = {
    type: "SEQUENCE",
    value: {
        type: {type: "OBJECT_IDENTIFIER", index: 0},
        values: {
            type: "SET",
            minOccurs: 1,
            maxOccurs: trusted.MAX,
            value: {
                v: {type: "ANY"}
            }
        }
    }
};



trusted.schemas.PFX = {
    type: "SEQUENCE",
    value: {
        version: {type: "INTEGER", index: 0}, // {v3(3)}(v3,...),
        authSafe: {type: "ContentInfo", index: 1},
        macData: {type: "MacData", optional: true, index: 2}
    }

};

trusted.schemas.MacData = {
    type: "SEQUENCE",
    value: {
        mac: {type: "DigestInfo", index: 0},
        macSalt: {type: "OCTET_STRING", index: 1},
        iterations: {type: "INTEGER", default: 1, index: 2}
    }
};

trusted.schemas.AuthenticatedSafe = {
    type: "SEQUENCE",
    maxOccurs: trusted.MAX,
    value: {
        v: {type: "ContentInfo"}
    }
};
//-- Data if unencrypted
//-- EncryptedData if password-encrypted
//-- EnvelopedData if public key-encrypted

trusted.schemas.SafeContents = {
    type: "SEQUENCE",
    maxOccurs: trusted.MAX,
    value: {
        v: {type: "SafeBag"}
    }
};


trusted.schemas.SafeBag = {
    type: "SEQUENCE",
    value: {
        bagId: {type: "OBJECT_IDENTIFIER", index: 0},
        bagValue: {type: "ANY", context: 0, explicit: true, index: 1},
        bagAttributes: {type: "SET", maxOccurs: trusted.MAX, optional: true, value: {type: "Attribute"}, index: 2}
    }

};
if (window.trusted === undefined)
    window.trusted = {};
if (window.trusted.schemas === undefined)
    window.trusted.schemas = {};

(function(namespace) {
    namespace.ContentInfo = {
        type: "SEQUENCE",
        value: {
            contentType: {type: "ContentType", index: 0},
            content: {type: "ANY", optional: true, context: 0}
        }
    };

    namespace.ContentType = {
        type: "OBJECT_IDENTIFIER"
    };

    /*
     data OBJECT IDENTIFIER :: = { pkcs - 7 1 }
     signedData OBJECT IDENTIFIER :: = { pkcs - 7 2 }
     envelopedData OBJECT IDENTIFIER :: = { pkcs - 7 3 }
     signedAndEnvelopedData OBJECT IDENTIFIER :: = { pkcs - 7 4 }
     digestedData OBJECT IDENTIFIER :: = { pkcs - 7 5 }
     encryptedData OBJECT IDENTIFIER :: = { pkcs - 7 6 }
     */

    namespace.SignedData = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            digestAlgorithms: {type: "DigestAlgorithmIdentifiers", index: 1},
            contentInfo: {type: "ContentInfo", index: 2},
            certificates: {type: "ExtendedCertificatesAndCertificates", context: 0, implicit: true, index: 3, optional: true},
            crls: {type: "CertificateRevocationLists", context: 1, implicit: true, index: 4, optional: true},
            signerInfos: {type: "SignerInfos", index: 5}
        }
    };

    namespace.DigestEncryptionAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };

    namespace.DigestAlgorithmIdentifiers = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            digestAlgorithmIdentifier: {type: "DigestAlgorithmIdentifier"}
        }
    };

    namespace.DigestAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };

    namespace.SignerInfos = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            signerInfo: {type: "SignerInfo"}
        }
    };

    namespace.SignerInfo = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            issuerAndSerialNumber: {type: "IssuerAndSerialNumber", index: 1},
            digestAlgorithm: {type: "DigestAlgorithmIdentifier", index: 2},
            authenticatedAttributes: {type: "Attributes", context: 0, implicit: true, index: 3, optional: true},
            digestEncryptionAlgorithm: {type: "DigestEncryptionAlgorithmIdentifier", index: 4},
            encryptedDigest: {type: "EncryptedDigest", index: 5},
            unauthenticatedAttributes: {type: "Attributes", context: 1, implicit: true, index: 6, optional: true}
        }
    };

    namespace.EncryptedDigest = {
        type: "OCTET_STRING"
    };

    namespace.ContentInfo = {
        type: "SEQUENCE",
        value: {
            contentType: {type: "ContentType", index: 0},
            content: {type: "ANY", explicit: true, context: 0, optional: true, index: 1}
        }
    };

    namespace.ContentType = {
        type: "OBJECT_IDENTIFIER"
    };

    namespace.ExtendedCertificatesAndCertificates = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            extendedCertificateOrCertificate: {type: "ExtendedCertificateOrCertificate"}
        }
    };

    namespace.IssuerAndSerialNumber = {
        type: "SEQUENCE",
        value: {
            issuer: {type: "Name", index: 0},
            serialNumber: {type: "CertificateSerialNumber", index: 1}
        }
    };

    namespace.ExtendedCertificateOrCertificate = {
        type: "CHOICE",
        value: {
            certificate: {type: "ANY"}, // X.509  - Certificate / + ANY
            extendedCertificate: {type: "ExtendedCertificate", context: 0, implicit: true}  // rfc5652
        }
    };

    namespace.ExtendedCertificate = {
        type: "SEQUENCE",
        value: {
            extendedCertificateInfo: {type: "ExtendedCertificateInfo", index: 0},
            signatureAlgorithm: {type: "SignatureAlgorithmIdentifier", index: 1},
            signature: {type: "Signature", index: 2}
        }
    };

    namespace.ExtendedCertificateInfo = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version"},
            certificate: {type: "Certificate"},
            attributes: {type: "Attributes"}
        }
    };

    namespace.SignatureAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };

    namespace.Signature = {
        type: "BIT_STRING"
    };

    namespace.CertificateRevocationLists = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "CertificateRevocationList"}
        }
    };

    namespace.CertificateRevocationList = {
        type: "SEQUENCE",
        value: {
            signature: {type: "AlgorithmIdentifier", index: 0},
            issuer: {type: "Name", index: 1},
            lastUpdate: {type: "UTC_TIME", index: 2},
            nextUpdate: {type: "UTC_TIME", index: 3},
            revokedCertificates: {
                type: "SEQUENCE",
                maxOccurs: trusted.MAX,
                optional: true,
                index: 4,
                value: {
                    v: {type: "CRLEntry"}
                }
            }
        }
    };

    namespace.CRLEntry = {
        type: "SEQUENCE",
        value: {
            userCertificate: {type: "CertificateSerialNumber", index: 0},
            revocationDate: {type: "UTC_TIME", index: 1}
        }
    };

    // SigneDataContent
    namespace.DataContent = {
        type: "OCTET_STRING",
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "OCTET_STRING"}
        }
    };

    namespace.DigestInfo = {
        type: "SEQUENCE",
        value: {
            digestAlgorithm: {type: "DigestAlgorithmIdentifier", index: 0},
            digest: {type: "Digest", index: 1}
        }
    };

    namespace.Digest = {type: "OCTET_STRING"};

    //EncryptedData
    namespace.EncryptedData = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            encryptedContentInfo: {type: "EncryptedContentInfo", index: 1}
        }
    };

    namespace.EncryptedContentInfo = {
        type: "SEQUENCE",
        value: {
            contentType: {type: "ContentType", index: 0},
            contentEncryptionAlgorithm: {type: "ContentEncryptionAlgorithmIdentifier", index: 1},
            encryptedContent: {type: "EncryptedContent", context: 0, implicit: true, optional: true, index: 2}
        }
    };

    namespace.EncryptedContent = {type: "OCTET_STRING"};

    namespace.ContentEncryptionAlgorithmIdentifier = {type: "AlgorithmIdentifier"};

    namespace.EnvelopedData = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            recipientInfos: {type: "RecipientInfos", index: 1},
            encryptedContentInfo: {type: "EncryptedContentInfo", index: 2}
        }
    };

    namespace.RecipientInfos = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "RecipientInfo"}}
    };

    namespace.RecipientInfo = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            issuerAndSerialNumber: {type: "IssuerAndSerialNumber", index: 1},
            keyEncryptionAlgorithm: {type: "KeyEncryptionAlgorithmIdentifier", index: 2},
            encryptedKey: {type: "EncryptedKey", index: 3}
        }
    };

    namespace.EncryptedKey = {type: "OCTET_STRING"};

    namespace.KeyEncryptionAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };


})(window.trusted.schemas);trusted.schemas.PKCS8 = {
    type: "SEQUENCE",
    value: {
        version: {type: "Version", index:0},
        algorithm: {type: "AlgorithmIdentifier", index:1},
        key: {type: "OCTET_STRING", index:2}
    }
};
trusted.schemas.PKCS9String = {
    type: "CHOICE",
    value: {
        ia5String: {type: "IA5_STRING"}, //(SIZE(1..maxSize)),
        directoryString: {type: "DirectoryString"} //{maxSize}
    }
};

// Challenge password 1.2.840.113549.1.9.7
trusted.schemas.ChallengePassword = {
    type: "DirectoryString"
};
// Unstructured Name 1.2.840.113549.1.9.2
trusted.schemas.UnstructuredName = {
    type: "PKCS9String"
};

// Extension request 1.3.6.1.4.1.311.2.1.14
trusted.schemas.ExtensionRequest= {
    type: "Extensions"
};

if (window.trusted.schemas === undefined)
    window.trusted.schemas = {};
(function(namespace) {

    namespace.Certificate = {
        type: "SEQUENCE",
        value: {
            tbsCertificate: {type: "TBSCertificate", index: 0},
            signatureAlgorithm: {type: "AlgorithmIdentifier", index: 1},
            signature: {type: "BIT_STRING", index: 2}
        }
    };
    namespace.TBSCertificate = {
        type: "SEQUENCE",
        value: {
            version: {index: 0, type: "Version", optional: true, context: 0, default: 0, explicit: true},
            serialNumber: {index: 1, type: "CertificateSerialNumber"},
            signature: {index: 2, type: "AlgorithmIdentifier"},
            issuer: {index: 3, type: "Name"},
            validity: {index: 4, type: "Validity"},
            subject: {index: 5, type: "Name"},
            subjectPublicKeyInfo: {index: 6, type: "SubjectPublicKeyInfo"},
            issuerUniqueID: {index: 7, optional: true, implicit: true, type: "UniqueIdentifier", context: 1},
            subjectUniqueID: {index: 8, optional: true, implicit: true, type: "UniqueIdentifier", context: 2},
            extensions: {index: 9, optional: true, context: 3, type: "Extensions", explicit: true}
        }
    };
    namespace.Version = {
        type: "INTEGER"
    };
    namespace.CertificateSerialNumber = {
        type: "INTEGER"
    };
    namespace.Validity = {
        type: "SEQUENCE",
        value: {
            notBefore: {index: 0, type: "Time"},
            notAfter: {index: 1, type: "Time"}
        }
    };
    namespace.Time = {
        type: "CHOICE",
        value: {
            utcTime: {type: "UTC_TIME"},
            generalTime: {type: "GENERALIZED_TIME"}
        }
    };
    namespace.UniqueIdentifier = {
        type: "BIT_STRING"
    };
    namespace.SubjectPublicKeyInfo = {
        type: "SEQUENCE",
        value: {
            algorithm: {index: 0, type: "AlgorithmIdentifier"},
            subjectPublicKey: {index: 1, type: "BIT_STRING"}
        }
    };
    namespace.Extensions = {
        type: "SEQUENCE",
        minOccurs: 0,
        maxOccurs: trusted.MAX,
        value: {
            extension: {type: "Extension"}
        }
    };
    namespace.Extension = {
        type: "SEQUENCE",
        value: {
            extnID: {index: 0, type: "OBJECT_IDENTIFIER"},
            critical: {index: 1, type: "BOOLEAN", default: false},
            extnValue: {index: 2, type: "OCTET_STRING"}
        }
    };

    namespace.AlgorithmIdentifier = {
        type: "SEQUENCE",
        value: {
            algorithm: {index: 0, type: "OBJECT_IDENTIFIER"},
            parameters: {index: 1, type: "ANY", optional: true}
        }
    };
    namespace.Name = {
        type: "CHOICE",
        value: {
            rdnSequence: {type: "RDNSequence"}
        }
    };
    namespace.RDNSequence = {
        type: "SEQUENCE",
        maxOccurs: trusted.MAX,
        value: {
            rdn: {type: "RelativeDistinguishedName"}
        }
    };
    namespace.RelativeDistinguishedName = {
        type: "SET",
        minOccurs: 0,
        maxOccurs: trusted.MAX,
        value: {
            attribute: {type: "AttributeTypeAndValue"}
        }
    };
    namespace.AttributeTypeAndValue = {
        type: "SEQUENCE",
        value: {
            type: {type: "AttributeType"},
            value: {type: "AttributeValue"}
        }
    };
    namespace.AttributeType = {
        type: "OBJECT_IDENTIFIER"
    };
    namespace.AttributeValue = {
        type: "ANY" //-- DEFINED BY AttributeType
    };
    namespace.DirectoryString = {
        type: "CHOICE",
        value: {
            teletexString: {type: "T61_STRING"}, // SIZE (1..trusted.MAX)
            printableString: {type: "PRINTABLE_STRING"}, // SIZE (1..trusted.MAX)
            universalString: {type: "UNIVERSAL_STRING"}, // SIZE (1..trusted.MAX)
            utf8String: {type: "UTF8_STRING"}, // SIZE (1..trusted.MAX)
            bmpString: {type: "BMP_STRING"} // SIZE (1..trusted.MAX)
        }
    };

    namespace.GeneralNames = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            generalName: {type: "GeneralName"}
        }
    };

    namespace.GeneralName = {
        type: "CHOICE",
        value: {
            otherName: {type: "OtherName", context: 0},
            rfc822Name: {type: "IA5_STRING", context: 1},
            dNSName: {type: "IA5_STRING", context: 2},
            //x400Address: {type: "ORAddress", context: 3},
            directoryName: {type: "Name", context: 4},
            //ediPartyName: {type: "EDIPartyName", context: 5},
            uniformResourceIdentifier: {type: "IA5_STRING", context: 6},
            iPAddress: {type: "OCTET_STRING", context: 7},
            registeredID: {type: "OBJECT_IDENTIFIER", context: 8}
        }
    };

    namespace.OtherName = {
        type: "SEQUENCE",
        value: {
            typeId: {type: "OBJECT_IDENTIFIER", index: 0},
            value: {type: "ANY", context: 0, explicit: true, index: 1}
        }
    };

    namespace.EDIPartyName = {
        type: "SEQUENCE",
        value: {
            nameAssigner: {type: "DirectoryString", context: 0, optional: true},
            partyName: {type: "DirectoryString", context: 1}
        }
    };

    // Certificate Extensions
    // 2.5.29.1
    namespace.AuthorityKeyIdentifier1 = {
        type: "SEQUENCE",
        value: {
            keyIdentifier: {type: "KeyIdentifier", optional: true, context: 0, index: 0},
            authorityCertIssuer: {type: "Name", optional: true, context: 1, index: 1},
            authorityCertSerialNumber: {type: "CertificateSerialNumber", optional: true, context: 2, index: 2}
        }
    };
    // 2.5.29.35
    namespace.AuthorityKeyIdentifier2 = {
        type: "SEQUENCE",
        value: {
            keyIdentifier: {type: "KeyIdentifier", context: 0, optional: true, index: 0},
            authorityCertIssuer: {type: "GeneralNames", optional: true, context: 1, index: 1},
            authorityCertSerialNumber: {type: "CertificateSerialNumber", optional: true, context: 2, index: 2}
        }
    };

    namespace.KeyIdentifier = {
        type: "OCTET_STRING"
    };

    namespace.KeyUsage = {
        type: "BIT_STRING"
    };

    namespace.BasicConstraints = {
        type: "SEQUENCE",
        value: {
            cA: {type: "BOOLEAN", default: false},
            pathLenConstraint: {type: "INTEGER", optional: true} // (0..trusted.MAX)
        }
    };

    namespace.IssuerSignTool = {
        type: "SEQUENCE",
        value: {
            signTool: {type: "UTF8_STRING"}, //SIZE(1.200),
            cATool: {type: "UTF8_STRING"}, // SIZE(1..200),
            signToolCert: {type: "UTF8_STRING"}, //SIZE(1.. 100),
            cAToolCert: {type: "UTF8_STRING"} //SIZE(1.100) 
        }
    };
    namespace.SubjectSignTool = {
        type: "UTF8_STRING" //SIZE(1.200)
    };

    //2.5.29.8
    namespace.IssuerAlternativeName1 = {
        type: "GeneralName"
    };
    //2.5.29.18
    namespace.IssuerAlternativeName2 = {
        type: "GeneralNames"
    };
    namespace.SubjectAlternativeName = {
        type: "GeneralNames"
    };

    namespace.SubjectKeyIdentifier = {
        type: "KeyIdentifier"
    };

    namespace.CRLDistributionPoints = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            distributionPoint: {type: "DistributionPoint"}
        }
    };

    namespace.FreshestCRL = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            distributionPoint: {
                type: "DistributionPoint"
            }
        }
    };

    namespace.DistributionPoint = {
        type: "SEQUENCE",
        value: {
            distributionPoint: {type: "DistributionPointName", optional: true, context: 0},
            reasons: {type: "ReasonFlags", optional: true, context: 1},
            cRLIssuer: {type: "GeneralNames", optional: true, context: 2}
        }
    };

    namespace.DistributionPointName = {
        type: "CHOICE",
        value: {
            fullName: {type: "GeneralNames", context: 0},
            nameRelativeToCRLIssuer: {type: "RelativeDistinguishedName", context: 1}
        }
    };

    namespace.ReasonFlags = {
        type: "BIT_STRING"
    };

    namespace.ExtKeyUsageSyntax = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            keyPurposeId: {type: "KeyPurposeId"}
        }
    };

    namespace.KeyPurposeId = {
        type: "OBJECT_IDENTIFIER"
    };

    // CertificatPolicies 2.5.29.32
    namespace.CertificatePolicies = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            policyInformation: {type: "PolicyInformation"}
        }
    };

    namespace.PolicyInformation = {
        type: "SEQUENCE",
        value: {
            policyIdentifier: {type: "CertPolicyId", index: 0},
            policyQualifiers: {type: "PolicyQualifiers", index: 1, optional: true}
        }
    };

    namespace.PolicyQualifiers = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            policyQualifierInfo: {type: "PolicyQualifierInfo"}
        }
    };

    namespace.CertPolicyId = {type: "OBJECT_IDENTIFIER"};

    namespace.PolicyQualifierInfo = {
        type: "SEQUENCE",
        value: {
            policyQualifierId: {type: "PolicyQualifierId", index: 0},
            qualifier: {type: "ANY", index: 1}
        }
    };

    namespace.PolicyQualifierId = {type: "OBJECT_IDENTIFIER"};

    namespace.Qualifier = {
        type: "CHOICE",
        value: {
            cPSuri: {type: "CPSuri"},
            userNotice: {type: "UserNotice"}
        }
    };

    namespace.CPSuri = {type: "IA5_STRING"};

    namespace.UserNotice = {
        type: "SEQUENCE",
        value: {
            noticeRef: {type: "NoticeReference", optional: true, index: 0},
            explicitText: {type: "DisplayText", optional: true, index: 1}
        }
    };

    namespace.NoticeReference = {
        type: "SEQUENCE",
        value: {
            organization: {type: "DisplayText", index: 0},
            noticeNumbers: {type: "NoticeNumbers", index: 1}
        }
    };
    namespace.NoticeNumbers = {
        type: "SEQUENCE",
        maxOccurs: trusted.MAX,
        value: {
            val: {type: "INTEGER"}
        }
    };

    namespace.DisplayText = {
        type: "CHOICE",
        value: {
            ia5String: {type: "IA5_STRING"}, //(SIZE (1..200)),
            visibleString: {type: "ISO64_STRING"}, //(SIZE (1..200)),
            bmpString: {type: "BMP_STRING"}, //(SIZE (1..200)),
            utf8String: {type: "UTF8_STRING"}     //(SIZE (1..200)) }
        }
    };

    namespace.AuthorityInfoAccessSyntax = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "AccessDescription"}
        }
    };

    namespace.AccessDescription = {
        type: "SEQUENCE",
        value: {
            accessMethod: {type: "OBJECT_IDENTIFIER", index: 0},
            accessLocation: {type: "GeneralName", index: 1}
        }
    };

    namespace.SubjectInfoAccessSyntax = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "AccessDescription"}
        }
    };

    namespace.PrivateKeyUsagePeriod = {
        type: "SEQUENCE",
        value: {
            notBefore: {type: "GENERALIZED_TIME", optional: true, context: 0},
            notAfter: {type: "GENERALIZED_TIME", optional: true, context: 1}
        }
    };

    // CRL

    namespace.CertificateList = {
        type: "SEQUENCE",
        value: {
            tbsCertList: {type: "TBSCertList", index: 0},
            signatureAlgorithm: {type: "AlgorithmIdentifier", index: 1},
            signatureValue: {type: "BIT_STRING", index: 2}
        }
    };
    namespace.TBSCertList = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", optional: true, index: 0},
            signature: {type: "AlgorithmIdentifier", index: 1},
            issuer: {type: "Name", index: 2},
            thisUpdate: {type: "Time", index: 3},
            nextUpdate: {type: "Time", optional: true, index: 4},
            revokedCertificates: {type: "RevokedCertificates", index: 5, optional: true},
            crlExtensions: {type: "Extensions", context: 0, explicit: true, optional: true, index: 6}
        }

    };
    namespace.RevokedCertificates = {
        type: "SEQUENCE",
        maxOccurs: trusted.MAX,
        value: {revokedCertificate: {type: "RevokedCertificate"}}
    };

    namespace.RevokedCertificate = {
        type: "SEQUENCE",
        value: {
            userCertificate: {type: "CertificateSerialNumber", index: 0},
            revocationDate: {type: "Time", index: 1},
            crlEntryExtensions: {type: "Extensions", optional: true, index: 2}
        }
    };

    // CRL Extensions
    // CRL Number 2.5.29.20
    namespace.CRLNumber = {
        type: "INTEGER" // (0..trusted.MAX)
    };

    // Delta CRL Indicator 2.5.29.27    
    namespace.BaseCRLNumber = {
        type: "CRLNumber"
    };

    // Issuing Distribution Point 2.5.29.28
    namespace.IssuingDistributionPoint = {
        type: "SEQUENCE",
        value: {
            distributionPoint: {type: "DistributionPointName", context: 0, optional: true, index: 0},
            onlyContainsUserCerts: {type: "BOOLEAN", context: 1, default: false, index: 1},
            onlyContainsCACerts: {type: "BOOLEAN", context: 2, default: false, index: 2},
            onlySomeReasons: {type: "ReasonFlags", context: 3, optional: true},
            indirectCRL: {type: "BOOLEAN", context: 4, default: false},
            onlyContainsAttributeCerts: {type: "BOOLEAN", context: 5, default: false}
        }
    };

    // 5.3.  CRL Entry Extensions
    // Reason Code 2.5.29.21
    namespace.ReasonCode = {
        type: "ENUMERATED"
                /*
                 unspecified             (0),
                 keyCompromise           (1),
                 cACompromise            (2),
                 affiliationChanged      (3),
                 superseded              (4),
                 cessationOfOperation    (5),
                 certificateHold         (6),
                 -- value 7 is not used
                 removeFromCRL           (8),
                 privilegeWithdrawn      (9),
                 aACompromise           (10
                 */
    };

    // Invalidity Date 2.5.29.24
    namespace.InvalidityDate = {
        type: "GENERALIZED_TIME"
    };
    
    // Certificate Issuer 2.5.29.29
    namespace.CertificateIssuer = {
        type:"GeneralNames"
    };

    // Keys
    namespace.RSAPublicKey = {
        type: "SEQUENCE",
        value: {
            modulus: {type: "INTEGER", index: 0},
            publicExponent: {type: "INTEGER", index: 1}
        }
    };

    namespace.RSAPrivateKey = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version"},
            modulus: {type: "INTEGER"},
            publicExponent: {type: "INTEGER"},
            privateExponent: {type: "INTEGER"},
            prime1: {type: "INTEGER"},
            prime2: {type: "INTEGER"},
            exponent1: {type: "INTEGER"},
            exponent2: {type: "INTEGER"},
            coefficient: {type: "INTEGER"}
        }
    };

    namespace.GOSTPublicKey = {
        type: "OCTET_STRING"
    };

})(window.trusted.schemas);
})();

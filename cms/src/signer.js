function Signer() {
    var obj, cache;
    this.__proto__ = {
        get digestAlgorithm() {
            if (cache.cert !== null)
                return this.certificate.publicKey.algorithm;
            else {
                if (cache.alg === undefined)
                    cache.alg = new trusted.PKI.Algorithm(obj.digestAlgorithm);
                return cache.alg;
            }
        },
        get certificateID() {
            if (cache.cert === null) {
                if (cache.certID === null)
                    cache.certID = new CertID(
                            new trusted.PKI.Name(obj.issuerAndSerialNumber.issuer),
                            obj.issuerAndSerialNumber.serialNumber);
            }
            else {
                if (cache.certID === null || cache.certID === undefined)
                    cache.certID = new CertID(this.certificate);
            }
            return cache.certID;
        },
        get version() {
            if (cache.v === undefined) {
                cache.v = 1;
                if (obj.version !== undefined)
                    cache.v = obj.version;
            }
            return cache.v;
        },
        get signatureAlgorithm() {
            if (cache.cert === null) {
                if (cache.siga === undefined) {
                    cache.siga = new trusted.PKI.Algorithm(obj.digestEncryptionAlgorithm);
                }
            }
            else
                return null;
            return cache.siga;
        },
        get signature() {
            if (cache.cert === null) {
                if (cache.sig === undefined) {
                    cache.sig = new BitString(obj.encryptedDigest, 0);
                }
            }
            else
                return null;
            return cache.sig;
        },
        get attributes() {
            if (cache.attrs === undefined) {
                cache.attrs = [];
                if (cache.cert === null) {
                    cache.attrs = cache.attrs.concat(getAttributes(obj.authenticatedAttributes, true));
                    cache.attrs = cache.attrs.concat(getAttributes(obj.unauthenticatedAttributes, false));
                }
            }
            return cache.attrs;
        },
        set certificate(v) {
            refreshVars.call(this);
            cache.cert = v;
        },
        get certificate() {
            return cache.cert;
        }
    };

    this.__proto__.verify = function(key, hash) {
        var _this = this;
        var key = null;
        var publicKey = null;
        var sequence = new Promise(function(resolve, reject) {
            // get parameter
            if (key === undefined)
                reject("Signer.verify: Параметр не может быть Undefined.");
            switch (key.type) {
                case "PublicKey":
                    publicKey = key;
                    break;
                case "Certificate":
                    publicKey = key.publicKey;
                    break;
                default:
                    throw "Signer.verify: Параметр несоответствующего класса.";
            }
            
            var keyData = Der.toUint8Array(publicKey.encode());
            var usages = ['verify'];
            var extractable = false;

            // (1) Import the key
            trusted.Crypto.importKey('spki', keyData, publicKey.algorithm.crypto, extractable, usages).then(
                    function(result) {
                        key = result;
                        return Promise.resolve();
                    },
                    function(err) {
                        return Promise.reject("ImportKey: " + err);
                    }
            // (2) Verify certificate signature
            ).then(
                    function(res) {
                        console.log(_this);
                        return trusted.Crypto.verify(
                                _this.signers[0].signatureAlgorithm.crypto,
                                key,
                                Der.toUint8Array(_this.signers[0].signature.encoded),
                                Der.toUint8Array(_this.s)
                                );
                    },
                    function(err) {
                        return Promise.reject(err);
                    }
            ).then(
                    function(v) {
                        resolve(v);
                    },
                    function(err) {
                        reject(err);
                    }
            );
        });
        return sequence;
    };

    this.__proto__.getAttribute = function(oid) {
        if (trusted.isString(oid))
            oid = new trusted.PKI.OID(oid);
        for (var i = 0; i < this.attributes.length; i++) {
            if (this.attributes[i].OID === oid.value)
                return this.attributes[i];
        }
        return null;
    };
    function getAttributes(attrs, signed) {
        var r = [];
        if (attrs !== null) {
            for (var i = 0; i < attrs.length; i++) {
                r.push(new SignerAttribute(attrs[i], signed));
            }
        }
        return r;
    }

    this.__proto__.toObject = function() {
        function getAttrs(attrs, auth) {
            var r = [];
            for (var i = 0; i < attrs.length; i++) {
                if (attrs[i].signed === auth)
                    r.push(attrs[i].toObject());
            }
            if (r.length === 0)
                r = null;
            return r;
        }
        var o = {
            version: this.version,
            issuerAndSerialNumber: this.certificateID.toObject(),
            digestAlgorithm: this.digestAlgorithm.toObject(),
            digestEncryptionAlgorithm: this.signatureAlgorithm.toObject(),
            encryptedDigest: this.signature.encoded,
            authenticatedAttributes: getAttrs(this.attributes, true),
            unauthenticatedAttributes: getAttrs(this.attributes, false)
        };
        return o;
    };
    function refreshVars() {
        obj = {};
        cache = {cert: null, certID: null};
    }

    function init(args) {
        refreshVars.call(this);
        if (trusted.isString(args[0])) {
            var asn = new trusted.ASN(args[0]);
            args[0] = asn.toObject("SignerInfo");
        }
        if (!(trusted.isObject(args[0])))
            throw "Signer.new: Параметр имеет неверный формат.";
        if (trusted.isObject(args[1]))
            cache.cert = args[1];
        obj = args[0];
    }

    init.call(this, arguments);
}

function CertID() {

    this.issuerName = null;
    this.serialNumber = null;
    this.__proto__.toObject = function() {
        var o = {
            issuer: this.issuerName.toObject(),
            serialNumber: this.serialNumber
        };
        return o;
    };
    function init(args) {
        switch (args.length) {
            case 0:
                break;
            case 1:
                if (!trusted.isObject(args[0]))
                    throw "CertID.new: Праметр должен быть обектом Certificate."
                this.issuerName = args[0].issuerName;
                this.serialNumber = args[0].serialNumber;
                break;
            default: // >=2
                this.issuerName = args[0];
                this.serialNumber = args[1];
        }
    }

    init.call(this, arguments);
}


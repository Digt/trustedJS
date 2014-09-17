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
            if (obj.issuerAndSerialNumber !== null) {
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
            if (obj.digestEncryptionAlgorithm !== null) {
                if (cache.siga === undefined) {
                    cache.siga = new trusted.PKI.Algorithm(obj.digestEncryptionAlgorithm);
                }
            }
            else
                return null;
            return cache.siga;
        },
        get signature() {
            if (obj.encryptedDigest !== null) {
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
                cache.attrs = cache.attrs.concat(getAttributes(obj.authenticatedAttributes, true));
                cache.attrs = cache.attrs.concat(getAttributes(obj.unauthenticatedAttributes, false));
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

    // return attributes signed | not signed
    function getAttrs(attrs, auth) {
        var r = [];
        for (var i = 0; i < attrs.length; i++) {
            if (attrs[i].signed === auth)
                r.push(attrs[i].toObject());
        }
        //if (r.length === 0)
        //    r = null;
        return r;
    }

    this.__proto__.hasSignedAttributes = function() {
        return getAttrs(this.attributes, true).length > 0;
    };

    function getSignedAttributesDer(algorithm) {
        var data = null;
        if (this.hasSignedAttributes()) {
            // encode signed attributes
            data = trusted.ASN.fromObject(obj.authenticatedAttributes, "Attributes").encode();
        }
        return data;
    }

    this.__proto__.verify = function(content, key) {
        var _this = this;
        var publicKey = null;
        var data = null;
        var sequence = new Promise(function(resolve, reject) {
            // get content

            if (_this.hasSignedAttributes())
                data = getSignedAttributesDer.call(_this); // get signed attributes
            else if (content !== undefined)
                data = content; // get content
            else
                reject("Signer.verify: Отсутствует содержимое для проверки.");

            //-----
            if (_this.certificate !== null)
                key = _this.certificate.publicKey;
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
            var promise = trusted.Crypto.importKey('spki', keyData, publicKey.algorithm.crypto, extractable, usages).then(
                    function(result) {
                        key = result;
                        return Promise.resolve();
                    },
                    function(err) {
                        reject(err);
                    }
            );

            if (content !== data) {
                //get hash for content
                promise = promise.then(
                        function() {
                            return trusted.Crypto.digest(key.algorithm.hash, Der.toUint8Array(content)).then(
                                    function(digest) {
                                        var hash = String.fromCharCode.apply(null, new Uint8Array(digest));
                                        var asn = new trusted.ASN(_this.getAttribute("1.2.840.113549.1.9.4").value);
                                        var attr_hex = asn.toObject("OCTET_STRING");
                                        if (hash===attr_hex)
                                            return Promise.resolve();
                                        else
                                            reject("Signer.verify: Hash of content is not equals signed hash.");
                                    },
                                    function(error) {
                                        reject("Signer.getHash: " + error);
                                    }
                            );
                        }
                );
            }

            // (2) Verify certificate signature
            promise = promise.then(
                    function() {
                        return trusted.Crypto.verify(
                                _this.signatureAlgorithm.crypto,
                                key,
                                Der.toUint8Array(_this.signature.encoded),
                                Der.toUint8Array(data)
                                );
                    },
                    function(err) {
                        reject(err);
                    }
            ).then(
                    function(v) {
                        resolve({signer: _this, status: v});
                    },
                    function(err) {
                        reject({signer: _this, status: false, error: err});
                    }
            );
        });
        return sequence;
    };

    this.__proto__.getAttribute = function(oid) {
        if (trusted.isString(oid))
            oid = new trusted.PKI.OID(oid);
        for (var i = 0; i < this.attributes.length; i++) {
            if (this.attributes[i].OID.value === oid.value)
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


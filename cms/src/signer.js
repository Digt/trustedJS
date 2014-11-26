function Signer() {
    var obj, cache;
    this.__proto__ = {
        get digestAlgorithm() {
            if (cache.alg === undefined) {
                cache.alg = null;
                if (obj.digestAlgorithm !== undefined)
                    cache.alg = new trusted.PKI.Algorithm(obj.digestAlgorithm);
                else
                    cache.alg = this.certificate.publicKey.algorithm;
            }
            return cache.alg;
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
    
    this.__proto__.toObject = function(){
        var o ={
            version: 1,
            issuerAndSerialNumber: this.certificateID.toObject(),
            digestAlgorithm: this.signatureAlgorithm.toObject(),
            digestEncryptionAlgorithm: this.digestAlgorithm.toObject(),
            encryptedDigest: this.signature.encoded
        };
        var attrs = getAttrs(this.attributes,true);
        if (attrs.length>0){
            o.authenticatedAttributes =[];
            for (var i=0; i<attrs.length; i++)
                o.authenticatedAttributes.push(attrs[i]);
        }
        var attrs = getAttrs(this.attributes,false);
        if (attrs.length>0){
            o.unauthenticatedAttributes =[];
            for (var i=0; i<attrs.length; i++)
                o.unauthenticatedAttributes.push(attrs[i]);
        }
        return o;
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
        var data = null;
        var _this = this;
        if (key === undefined) {
            key = this.certificate.publicKey;
        }
        return new Promise(function(resolve, reject) {
            if (_this.hasSignedAttributes())
                data = getSignedAttributesDer.call(_this); // get signed attributes
            else
                data = content;
            var promise = Promise.resolve();
            // [0] get hash of content
            if (content !== data) {
                var digest = null;
                promise = promise.then(function() {
                    var hash = trusted.Crypto.createHash(_this.digestAlgorithm);
                    hash.update(content);
                    return hash.digest();
                }).then(function(v) {
                    digest = v;
                    // get attribute content hash
                    var attr = _this.getAttribute("1.2.840.113549.1.9.4");
                    var hash = new trusted.ASN(attr.value);
                    hash = hash.toObject("OCTET_STRING");
                    if (digest!==hash)
                        return reject(err_t+"Hash of content differs from signed hash");
                    return Promise.resolve();
                }).catch(function(e) {
                    return Promise.reject(e);
                });
            }
            // (1) verify data
            var algorithm=_this.signatureAlgorithm;
            if (algorithm.hash===null){
                switch(algorithm.OID.value){
                    case "1.2.840.113549.1.1.1": //rsaEncryption
                        algorithm=trusted.PKI.Algorithm.fromName("rsa-"+_this.digestAlgorithm.name);
                }
            }
            var verifier = trusted.Crypto.createVerify(algorithm);
            verifier.update(data);
            promise = promise.then(
                    function() {
                        return verifier.verify(key, _this.signature.encoded);
                    }).then(
                    function(v) {
                        resolve({signer: _this, status: v});
                    }).catch(function(err) {
                reject({signer: _this, status: false, error: err});
            });
        });
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
        if (attrs===undefined)
            attrs=[];
        if (attrs !== null) {
            for (var i = 0; i < attrs.length; i++) {
                r.push(new SignerAttribute(attrs[i], signed));
            }
        }
        return r;
    }

    function refreshVars() {
        obj = {};
        cache = {cert: null, certID: null};
    }

    function init(args) {
        refreshVars.call(this);
        v = objFromBuffer(v, "SignerInfo");
        if (!(trusted.isObject(args[0])))
            throw "Signer.new: Параметр имеет неверный формат.";
        if (args[1] !== null && trusted.isObject(args[1])) {
            if (args[1].type !== "Certificate")
                throw "Signer.new: Параметр certificate должен быть Certificate.";
            cache.cert = args[1];
        }
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

//export
trusted.CMS.Signer = Signer;
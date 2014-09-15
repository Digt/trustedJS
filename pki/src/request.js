(function() {

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
            if (trusted.isString(v)) {
                asn = new trusted.ASN(v);
                v = asn.toObject("CertificationRequest");
            }
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
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("Attribute");
            }
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



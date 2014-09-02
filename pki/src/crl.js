(function() {

    function CRL() {
        var obj;
        var cache;
        var df_version = 1;

        this.__proto__ = {
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
                if (obj.tbsCertList.nextUpdate === null)
                    return null;
                return (obj.tbsCertList.nextUpdate.utcTime === undefined)
                        ? obj.tbsCertList.nextUpdate.generalTime
                        : obj.tbsCertList.nextUpdate.utcTime;
            },
            set nextUpdate(v) {
            },
            get certificates() {
                if (cache.crts === undefined) {
                    var certs = obj.tbsCertList.revokedCertificates;
                    cache.certs = [];
                    for (var i = 0; i < certs.length; i++)
                        cache.certs.push(new RevokedCertificate(certs[i]));
                }
                return cache.certs;
            },
            set certificates(v) {
            },
            get extensions() {
                if (cache.extns === undefined) {
                    cache.extns = null;
                    var extns = obj.tbsCertList.crlExtensions;
                    if (extns !== null) {
                        cache.extns = [];
                        for (var i = 0; i < extns.length; i++)
                            cache.extns.push(extns[i]);
                    }
                }
                return cache.extns;
            },
            set extensions(v) {
            },
            set signature(v) {
            },
            get signature() {
                return obj.signatureValue;
            }
        };

        this.__proto__.verify = function() {
            //TODO: Провевить на равенство SignatureAlgorithm и tbsCertList.Signature
        };

        this.__proto__.getExtension = function(oid) {
            if (!(oid === undefined || this.extensions === null))
                return getExtnByOID(this.extensions, oid); // Возвращает Extension или null
            return null;
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.tbsCertLis = {
                version: this.version,
                signature: this.signatureAlgorithm.toObject(),
                issuer: this.issuerName.toObject(),
                thisUpdate: {generalTime: this.thisUpdate}
            };
            void (this.nextUpdate !== null) ? o.tbsCertLis.nextUpdate = {generalTime: this.nextUpdate} : null;
            if (this.certificates !== null) {
                var certs = [];
                for (var i = 0; i < this.certificates.length; i++)
                    certs.push(this.certificates[i].toObjcet());
                o.tbsCertLis.revokedCertificates = certs;
            }
            if (this.extensions !== null) {
                var extns = [];
                for (var i = 0; i < this.extensions.length; i++)
                    extns.push(this.extensions[i].toObjcet());
                o.tbsCertLis.crlExtensions = extns;
            }

            o.signatureAlgorithm = this.signatureAlgorithm.toObject();
            o.signatureValue = this.signature;

            return o;
        };


        // inicialization
        function init(v) {
            if (v === undefined)
                throw "CRL.new: Параметр не может быть Undefined";
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("CertificateList");
            if (!(trusted.isObject(v) || (true)))
                throw "CRL.new: Задан неверный параметр.";

            obj = v;
            cache = {};
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
                    cache.extns = null;
                    if (obj.crlEntryExtensions !== null) {
                        cache.extns = [];
                        for (var i = 0; i < obj.crlEntryExtensions.length; i++)
                            cache.extns.push(obj.crlEntryExtensions[i]);
                    }
                }
                return cache.extns;
            },
            set extensions(v) {
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
                    extns.push(this.extensions[i].toObjcet());
                o.crlEntryExtensions = extns;
            }

            return o;
        };

        // inicialization
        function init(v) {
            if (v === undefined)
                throw "RevokedCertificate.new: Параметр не может быть Undefined";
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("RevokedCertificate");
            if (!(trusted.isObject(v) || ("userCertificate" in v && "revocationDate" in v)))
                throw "RevokedCertificate.new: Задан неверный параметр.";

            obj = v;
            cache = {};
        }

        init.call(this, arguments[0]);
    }

    // export
    trusted.PKI.CRL = CRL;
})();
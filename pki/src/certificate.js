(function(undefined) {
    function Certificate() {
        var obj, asn;
        var cache = {};

        this.__proto__ = {
            set version(v) {
            },
            get version() {
                return obj.tbsCertificate.version;
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
                return asn.asn.sub[0].toString();
            },
            set subjectName(v) {
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
                    cache.extns = null;
                    if (obj.tbsCertificate.extensions !== undefined) {
                        cache.extns = [];
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
                    if (obj.tbsCertificate.issuerUniqueID !== undefined)
                        cache.iuid = obj.tbsCertificate.issuerUniqueID;
                }
                return cache.iuid;
            },
            set subjectUniqueID(v) {
            },
            get subjectUniqueID() {
                if (cache.suid === undefined) {
                    cache.suid = null;
                    if (obj.tbsCertificate.subjectUniqueID !== undefined)
                        cache.suid = obj.tbsCertificate.subjectUniqueID;
                }
                return cache.suid;
            }
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

        this.__proto__.basicConstraints = function() {
            if (cache.bc === undefined) { // cache
                cache.bc = this.getExtension("2.5.29.19");
                if (cache.bc) {
                    var asn = new trusted.ASN(cache.bc.extnValue);
                    cache.bc = new trusted.PKI.BasicConstraints(asn.toObject("BasicConstraints"));
                }
            }
            return cache.bc;
        };

        this.__proto__.keyUsage = function() {
            if (cache.ku === undefined) { // cache
                cache.ku = this.getExtension("2.5.29.15");
                if (cache.ku) {
                    var asn = new trusted.ASN(cache.ku.extnValue);
                    cache.ku = new trusted.PKI.KeyUsage(asn.toObject("KeyUsage"));
                }
            }
            return cache.ku;
        };

        this.__proto__.extendedKeyUsage = function() {
            if (cache.eku === undefined) { // cache
                cache.eku = this.getExtension("2.5.29.37");
                if (cache.eku) {
                    var asn = new trusted.ASN(cache.eku.extnValue);
                    cache.eku = new trusted.PKI.ExtendedKeyUsage(asn.toObject("ExtKeyUsageSyntax"));
                }
            }
          
            return cache.eku;
        };

        this.__proto__.issuerAlternativeName = function() {
            if (cache.ian === undefined) { // cache
                cache.ian = this.getExtension("2.5.29.18");
                if (cache.ian) {
                    var asn = new trusted.ASN(cache.ian.extnValue);
                    cache.ian = new trusted.PKI.IssuerAlternativeName(asn.toObject("IssuerAlternativeName2"));
                }
            }
            return cache.ian;
        };

        this.__proto__.subjectAlternativeName = function() {
            if (cache.san === undefined) { // cache
                cache.san = this.getExtension("2.5.29.17");
                if (cache.san) {
                    var asn = new trusted.ASN(cache.san.extnValue);
                    cache.san = new trusted.PKI.SubjectAlternativeName(asn.toObject("SubjectAlternativeName"));
                }
            }
            return cache.san;
        };

        this.__proto__.import = function() {
            cache = {}; // clear cashe
            asn = new trusted.ASN(arguments[0]);
            obj = asn.toObject("Certificate");
        };

        /**
         * Проверяет срок действия сертификата относительно заданной даты.
         * @param {Date} date Дата, относительно которой проверяется срок действия сертификата.
         * @returns {Boolean}
         */
        this.__proto__.checkValidity = function(date) {
            if (date === undefined)
                date = new Date();
            return (date >= this.notBefore && date < this.notAfter);
        };

        function init(args) {
            var certDer = args[0];
            if (certDer !== undefined && trusted.isString(certDer)) {
                this.import(certDer);
            }
        }

        init.call(this, arguments);
    }

    trusted.PKI.Certificate = Certificate;
})();
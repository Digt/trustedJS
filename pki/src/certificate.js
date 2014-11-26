(function(undefined) {
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
})();
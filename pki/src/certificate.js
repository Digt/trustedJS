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
                return cache.tbs;
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
                        var asn = new trusted.ASN(cache.bc.extnValue);
                        cache.bc = new trusted.PKI.BasicConstraints(asn.toObject("BasicConstraints"));
                    }
                }
                return cache.bc;
            },
            get keyUsage() {
                if (cache.ku === undefined) { // cache
                    cache.ku = this.getExtension("2.5.29.15");
                    if (cache.ku) {
                        var asn = new trusted.ASN(cache.ku.extnValue);
                        cache.ku = new trusted.PKI.KeyUsage(asn.toObject("KeyUsage"));
                    }
                }
                return cache.ku;
            },
            get extendedKeyUsage() {
                if (cache.eku === undefined) { // cache
                    cache.eku = this.getExtension("2.5.29.37");
                    if (cache.eku) {
                        var asn = new trusted.ASN(cache.eku.extnValue);
                        cache.eku = new trusted.PKI.ExtendedKeyUsage(asn.toObject("ExtKeyUsageSyntax"));
                    }
                }

                return cache.eku;
            },
            get issuerAlternativeName() {
                if (cache.ian === undefined) { // cache
                    cache.ian = this.getExtension("2.5.29.18");
                    if (cache.ian) {
                        var asn = new trusted.ASN(cache.ian.extnValue);
                        cache.ian = new trusted.PKI.IssuerAlternativeName(asn.toObject("IssuerAlternativeName2"));
                    }
                }
                return cache.ian;
            },
            get subjectAlternativeName() {
                if (cache.san === undefined) { // cache
                    cache.san = this.getExtension("2.5.29.17");
                    if (cache.san) {
                        var asn = new trusted.ASN(cache.san.extnValue);
                        cache.san = new trusted.PKI.SubjectAlternativeName(asn.toObject("SubjectAlternativeName"));
                    }
                }
                return cache.san;
            }
        };

        this.__proto__.isSelfSigned = function() {
            return this.subjectName.toString() === this.issuerName.toString();
        };

        this.__proto__.verify = function(issuerCert) {
            var key = null;
            var _this = this;
            if (issuerCert === undefined && !this.isSelfSigned())
                return Promise.reject("Certificate.verify: Параметр не может быть Undefined.");

            var keyData = Der.toUint8Array(issuerCert.publicKey.encode());
            var usages = ['verify'];
            var extractable = false;

            // (1) Import the key
            return crypto.subtle.importKey('spki', keyData, this.publicKey.algorithm.crypto, extractable, usages).then(
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
                        return trusted.Crypto.verify(
                                _this.signatureAlgorithm.crypto,
                                key,
                                Der.toUint8Array(_this.signature.encoded),
                                Der.toUint8Array(_this.TBSCertificate)
                                );
                    },
                    function(err) {
                        return Promise.reject(err);
                    }
            );
        };

        this.__proto__.getHash = function(alg) {
            if (alg === undefined)
                alg = {name: "SHA-1"};
            if (trusted.isString(alg))
                alg = {name: alg};
            cache.hash = undefined;
            return trusted.Crypto.digest(alg, Der.toUint8Array(this.encode())).then(
                    function(digest) {
                        return new Promise(
                                function(resolve, reject) {
                                    resolve(String.fromCharCode.apply(null, new Uint8Array(digest)));
                                }
                        );
                    },
                    function(error) {
                        return Promise.reject("Unable to get hash of certificate by '" + alg.name + "' algorithm.");
                    }
            );
        };

        this.__proto__.encode = function() {
            if (cache.encoded !== undefined) {
                return cache.encoded;
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
                this.import(cert);
            }
        }

        init.call(this, arguments);
    }

    trusted.PKI.Certificate = Certificate;
})();
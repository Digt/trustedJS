function SignedData() {
    var obj, cache;
    this.__proto__ = {
        get version() {
            if (obj === undefined) {
                return 1;
            }
            else {
                return obj.version;
            }
        },
        get digestAlgorithms() {
            if (cache.algs === undefined) {
                cache.algs = [];
                if (obj !== undefined)
                    var algs = {};
                for (var i = 0; i < obj.digestAlgorithms.length; i++) {
                    if (!(obj.digestAlgorithms[i].algorithm in algs)) {
                        algs[obj.digestAlgorithms[i].algorithm] = null;
                        cache.algs.push(new trusted.PKI.Algorithm(obj.digestAlgorithms[i]));
                    }
                }
            }
            return cache.algs;
        },
        get certificates() {
            if (cache.certs === undefined) {
                cache.certs = [];
                if (obj !== undefined && obj.certificates !== null)
                    for (var i = 0; i < obj.certificates.length; i++) {
                        if (!("certificate" in obj.certificates[i]))
                            throw "SignedData.certificate: ExtendedCerificate не поддерживается.";
                        cache.certs.push(new trusted.PKI.Certificate(obj.certificates[i].certificate));
                    }
            }
            return cache.certs;
        },
        get signers() {
            if (cache.signers === undefined) {
                cache.signers = [];
                if (obj !== undefined && obj.signers !== null)
                    for (var i = 0; i < obj.signerInfos.length; i++) {
                        var cert = new CertID(
                                new trusted.PKI.Name(obj.signerInfos[i].issuerAndSerialNumber.issuer),
                                obj.signerInfos[i].issuerAndSerialNumber.serialNumber
                                );
                        cache.signers.push(new Signer(obj.signerInfos[i], this.getCertificate(cert)));
                    }
            }
            return cache.signers;
        },
        set content(v) {
            if (!trusted.isString()) {
                "SignedData.content SET: Значение должно быть Строкой.";
            }
            if (cache.content !== v) {
                refreshVars();
                cache.content = v;
            }
        },
        get content() {
            if (cache.content === undefined) {
                cache.content = obj.contentInfo.content;
            }
            return cache.content;
        }
    };

    this.__proto__.getHash = function(algorithm) {
        if (algorithm === undefined)
            algorithm = {name: "SHA-1"};
        var sequence = new Promise(function(resolve, reject) {
            null;
        });
        return sequence;

    };

    this.__proto__.getCertificate = function(cert) {
        for (var i = 0; i < this.certificates.length; i++) {
            if (this.certificates[i].compare(cert))
                return this.certificates[i];
        }
    };

    function init(args) {
        refreshVars();
        switch (args.length) {
            case 0:
                break;
            default:
                var v = args[0];
                if (trusted.isString(v)) {
                    try {
                        v = new PKCS7(v);
                    }
                    catch (e) {
                        throw "SignedData.new: ASN пакет не соответствует структуре ASN PKCS7.";
                    }
                    if (v.OID.value !== "1.2.840.113549.1.7.2")
                        throw "SignedData.new: Тип PKCS7 не является SignedData.";
                    var asn = new trusted.ASN(v.content);
                    v = asn.toObject("SignedData");
                }
                obj = v;
        }
    }

    function refreshVars() {
        obj = undefined;
        cache = {};
    }

    init.call(this, arguments);
}
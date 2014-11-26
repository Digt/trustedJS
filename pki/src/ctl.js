function CTL() {
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
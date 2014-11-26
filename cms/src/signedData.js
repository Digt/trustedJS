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
                if (obj !== undefined) {
                    var algs = {};
                    for (var i = 0; i < obj.digestAlgorithms.length; i++) {
                        if (!(obj.digestAlgorithms[i].algorithm in algs)) {
                            algs[obj.digestAlgorithms[i].algorithm] = null;
                            cache.algs.push(new trusted.PKI.Algorithm(obj.digestAlgorithms[i]));
                        }
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
                cache.content = null;
                try {
                    // if content is array
                    var asn = new trusted.ASN(obj.contentInfo.content);
                    cache.content = asn.toObject("DataContent").join("");
                }
                catch (e) {
                    var asn = new trusted.ASN(obj.contentInfo.content);
                    cache.content = asn.toObject("OCTET_STRING");
                }
            }
            return cache.content;
        }
    };

    this.__proto__.getHash = function(algorithm, content) {
        if (algorithm === undefined)
            algorithm = trusted.PKI.Algorithm.fromName("sha1");
        if (content === undefined)
            content = this.content;
        var hash = trusted.Crypto.createHash(algorithm);
        hash.update(content);
        return hash.digest();
    };

    this.__proto__.verify = function(content, certs) {
        if (content === undefined)
            content = this.content;
        if (certs === undefined)
            certs = [];
        if (!trusted.isArray(certs))
            certs = [certs];

        var _this = this;

        var sequence = new Promise(function(resolve, reject) {
            // get certificates of Signers
            var signers = [];
            for (var i = 0; i < _this.signers.length; i++) {
                if (_this.signers[i].certificate !== null)
                    signers.push(_this.signers[i]); // get certificates from SignedData
                else
                    for (var j = 0; j < certs.length; j++)
                        if (certs[j].equals(_this.signer[i].certificateID))
                            signers.push(new Signer(obj.signerInfos[i], certs[j])); // get imported certificates
                        else
                            break;
            }
            if (signers.length !== _this.signers.length)
                reject("SignedData.verify: Указаны не все сертификаты подписчиков.");
            //-----

            // verifign signature for each signer
            var result = {status: true, signerInfos: []}; // init SignedData VerifyStatus
            var promises = [];
            for (var i = 0; i < signers.length; i++) {
                var signer = signers[i];
                promises.push(
                        signer.verify(content).then(
                        function(verify) {
                            if (!verify.status) {
                                result.status = false;
                            }
                            result.signerInfos.push(verify);
                        },
                        function(error) {
                            result.signerInfos.push(error);
                            result.status = false;
                        }
                ));
            }
            Promise.all(promises).then(
                    function() {
                        resolve(result);
                    }
            );

        });
        return sequence;
    };

    this.__proto__.sign = function(privateKey, certificate, content, certificates) {
        var err_t = "SignedData.sign: ";
        var _this = this;
        return new Promise(function(resolve, reject) {
            if (content===undefined){
                content = _this.content;
            }
            if (content===null){
                return reject(err_t+"Parameter 'content' can't be null");
            }

            var signer = new trusted.Crypto.createSign(privateKey.algorithm);
            console.log("Content:",content);
            signer.update(content);
            var signature;
            // (0) sign content
            signer.sign(privateKey).then(
                    function(v) {
                        signature = v;
                    }
            ).then(function(){
                // (1) create signerInfo
                var signer = {
                    version:1,
                    issuerAndSerialNumber:{
                        issuer: certificate.issuerName.toObject(),
                        serialNumber: certificate.serialNumber 
                    },
                    digestAlgorithm: trusted.PKI.Algorithm.fromName("rsa").toObject(),
                    digestEncryptionAlgorithm: trusted.PKI.Algorithm.fromName("sha1").toObject(),
                    encryptedDigest: signature
                };
                console.log(signer);
                _this.signers.push(new trusted.CMS.Signer(signer,certificate));
                _this.certificates.push(certificate);
                _this.digestAlgorithms.push(trusted.PKI.Algorithm.fromName("sha1"));
                console.log(Der.toHex(signature));
                var pkcs7= new trusted.PKI.PKCS7("signedData").toObject();
                var asn = trusted.ASN.fromObject(_this.toObject(),"SignedData");
                console.log(_this.toObject());
                pkcs7.content = asn.encode();
                asn = trusted.ASN.fromObject(pkcs7,"ContentInfo");
                resolve(asn.encode());
            }).catch(function(e){
                reject(e);
            });

        });
    };

    this.__proto__.toObject = function() {
        var o = {
            version: 0,
            digestAlgorithms: [],
            contentInfo: new trusted.PKI.PKCS7("data").toObject(),
            signerInfos: []
        };
        o.contentInfo.content=trusted.ASN.fromObject(this.content,"OCTET_STRING").encode();
        for (var i = 0; i < this.digestAlgorithms.length; i++)
            o.digestAlgorithms.push(this.digestAlgorithms[i].toObject());
        for (var i = 0; i < this.signers.length; i++)
            o.signerInfos.push(this.signers[i].toObject());
        if (this.certificates.length > 0) {
            o.certificates = [];
            for (var i = 0; i < this.certificates.length; i++)
                o.certificates.push({certificate: this.certificates[i].encode()});
        }
        return o;
    };

    this.__proto__.getCertificate = function(cert) {
        for (var i = 0; i < this.certificates.length; i++) {
            if (this.certificates[i].compare(cert))
                return this.certificates[i];
        }
        return null;
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
                    v = objFromBuffer(v.content, "SignedData");
                }
                obj = v;
                console.log("SignedData:", obj);
        }
    }

    function refreshVars() {
        obj = undefined;
        cache = {};
    }

    init.call(this, arguments);
}

//export
trusted.CMS.SignedData = SignedData;
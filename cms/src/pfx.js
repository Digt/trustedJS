function PFX() {
    var _obj, _cache;
    this.__proto__ = {
        get authSafe() {
            return parseAuthSafe(getAuthSafeData());
        }
    };
    this.__proto__.verifyPassword = function(v) {
        var salt = _obj.macData.macSalt;
        var iter = _obj.macData.iterations.toNumber();
        var dk = trusted.Crypto.pkcs12.keyGen(v, salt, iter);
        //console.log("DK verify:", dk.toString("hex"));
        var alg = new trusted.PKI.OID(_obj.macData.mac.digestAlgorithm.algorithm);
        var hmac = trusted.Crypto.createHmac(alg.name, dk);
        var data = (new trusted.ASN(_obj.authSafe.content)).toObject("OCTET_STRING");
        //console.log("Data verify:", data.toString("hex"));
        hmac.update(data);
        var res = hmac.final();
        return res.toString("hex") === _obj.macData.mac.digest.toString("hex");
    };
    /*
     * authSafe shall be of type data
     * or signedData
     */
    function getAuthSafeData() {
        var pkcs7 = new trusted.PKI.PKCS7(_obj.authSafe);
        switch (pkcs7.type) {
            case "data":
                return pkcs7.value;
            case "signedData":
                return new trusted.PKI.PKCS7(pkcs7.value.contentInfo).value;
        }
        return null;
    }

    /*
     * Read only Data and EncryptedData
     * 
     AuthenticatedSafe ::= SEQUENCE OF ContentInfo
     -- Data if unencrypted
     -- EncryptedData if password-encrypted
     // -- EnvelopedData if public key-encrypted // NOT USES
     */
    function parseAuthSafe(data) {
        var asn = new trusted.ASN(data);
        var obj = asn.toObject("AuthenticatedSafe");
        var res = [];
        for (var k in obj) {
            var pkcs7 = new trusted.PKI.PKCS7(obj[k]);
            if (pkcs7.type === "data" || pkcs7.type === "encryptedData")
                res.push(pkcs7);
        }
        return res;
    }

    this.extract = function(pass) {
        var safeBags = this.getSafeBags(pass);
        var keyBags = [];
        var certBags = [];
        for (var i in safeBags)
            switch (safeBags[i].type) {
                case "keyBag":
                case "pkcs8ShroudedKeyBag":
                    keyBags.push(safeBags[i]);
                    break;
                case "certBag":
                    certBags.push(safeBags[i]);
                    break;
            }
        var certs = [];
        for (var i in certBags) {
            var cert = certBags[i].value;
            if (certBags[i].localKeyId !== null)
                for (var j in keyBags)
                    if (keyBags[j].localKeyId === certBags[i].localKeyId) {
                        var key = null;
                        if (keyBags[j].type === "pkcs8ShroudedKeyBag")
                            key = new trusted.PKI.PrivateKeyInfo(keyBags[j].value.decrypt(pass));
                        else
                            key = keyBags[j].value;
                        cert.privateKey = new trusted.PKI.PrivateKey(key.content, key.algorithm);
                        break;
                    }
            certs.push(cert);
        }
        return certs;
    };

    this.getSafeBags = function(pass) {
        if (!this.verifyPassword(pass))
            throw "PFX: Wrang password!";
        var data = parseAuthSafe(getAuthSafeData());
        var res = [];
        for (var k in data) {
            if (data[k].type === "data") {
                var asn = new trusted.ASN(data[k].value);
                var sctx = asn.toObject("SafeContents");
                for (var i = 0; i < sctx.length; i++) {
                    var sb = new SafeBag(sctx[i]);
                    res.push(sb);
                }
            }
            if (data[k].type === "encryptedData") {
                var alg = new trusted.PKI.Algorithm(data[k].value.encryptedContentInfo.contentEncryptionAlgorithm);
                var ctx = data[k].value.encryptedContentInfo.encryptedContent;
                var der = trusted.Crypto.pkcs12.decrypt(alg.encode(), pass, ctx);
                var asn = new trusted.ASN(der);
                var sctx = asn.toObject("SafeContents");
                for (var i = 0; i < sctx.length; i++) {
                    var sb = new SafeBag(sctx[i]);
                    res.push(sb);
                }
            }
        }
        return res;
    };
    function init(args) {
        if (args[0] === undefined)
            throw "PFX.new: Параметр не может быть Undefined";
        var v = objFromBuffer(args[0], "PFX");
        if (!(trusted.isObject(v)))
            throw "PFX.new: Задан неверный параметр.";
        _obj = v;
        _cache = {};
    }

    init.call(this, arguments);
}

PFX.create = function(cert, pass) {
    var sbs = [];
    sbs[0] = new SafeBag(SafeBag.createCertBag(cert, "01"));
    //sbs[1] = new SafeBag(SafeBag.createKeyBag(cert.privateKey, "1", cert.subjectFriendlyName));
    var pfx = {
        version: 3
    };
    var authSafes = [];
    
    if (pass !== undefined) {
        var shroudedKey = SafeBag.createShroudedKeyBag(cert.privateKey, "1", "01");
        authSafes[0] = (new trusted.PKI.PKCS7(pfx_createData(new SafeBag(shroudedKey)))).toObject();
        authSafes[1] = (new trusted.PKI.PKCS7(pfx_createEncryptedData(sbs, pass))).toObject();
    } else {
        authSafes[0] = new trusted.PKI.PKCS7(pfx_createData(sbs)).toObject();
    }
    
    pfx.authSafe = new trusted.PKI.PKCS7(trusted.PKI.PKCS7.createData(trusted.ASN.fromObject(authSafes, "AuthenticatedSafe").blob())).toObject();
    
    var salt = trusted.Crypto.randomBytes(20);
    var iter = 2000;
    
    var key = trusted.Crypto.pkcs12.keyGen(pass, salt, iter);
    //console.log("DK create:", key.toString("hex"));
    var hmac = trusted.Crypto.createHmac("sha1", key);
    //console.log("Data verify:", pfx.authSafe.content.toString("hex"));
    hmac.update(new trusted.ASN(pfx.authSafe.content).toObject("OCTET_STRING"));
    var digest = hmac.final();
    
    pfx.macData ={
        mac:{
            digestAlgorithm:{algorithm:"1.3.14.3.2.26"},
                    digest: digest
        },
        macSalt: salt,
        iterations: iter
    };
    
    return trusted.ASN.fromObject(pfx, "PFX").blob();
};

function pfx_createData(safeBags) {
    if (!trusted.isArray(safeBags))
        safeBags = [safeBags];
    var sbs = [];
    for (var i in safeBags) {
        var sb = safeBags[i].toObject();
        sbs.push(sb);
    }
    var b = trusted.ASN.fromObject(sbs, "SafeContents").blob();

    return trusted.PKI.PKCS7.createData(b);
}

function pfx_createEncryptedData(safeBags, pass) {
    if (!trusted.isArray(safeBags))
        safeBags = [safeBags];
    var sbs = [];
    for (var i in safeBags) {
        var sb = safeBags[i].toObject();
        sbs.push(sb);
    }
    var b = trusted.ASN.fromObject(sbs, "SafeContents").blob();

    var params = trusted.ASN.fromObject(
            {
                salt: trusted.Crypto.randomBytes(8),
                iterations: 2000
            },
    "PBEParams"
            ).blob();
    var x509_alg = trusted.ASN.fromObject(
            {
                algorithm: "1.2.840.113549.1.12.1.6",
                parameters: params
            },
    "AlgorithmIdentifier"
            ).blob();

    var alg = new trusted.PKI.Algorithm(x509_alg);
    var encData = trusted.Crypto.pkcs12.encrypt(alg.encode(), pass, b);
    
    
    var eci = {
        contentType: trusted.PKI.PKCS7Types.data,
        contentEncryptionAlgorithm: alg.toObject(),
        encryptedContent: encData
    };
    var ed = {
        version:0,
        encryptedContentInfo:eci
    };
    return trusted.PKI.PKCS7.create("encryptedData", trusted.ASN.fromObject(ed, "EncryptedData").blob());
}

function SafeBag() {
    var _obj;
    this.__proto__ = {
        get id() {
            return new trusted.PKI.OID(_obj.bagId);
        },
        get content() {
            return _obj.bagValue;
        },
        get attributes() {
            var res = [];
            for (var i in _obj.bagAttributes) {
                res.push(new trusted.PKI.Attribute(_obj.bagAttributes[i]));
            }
            return res;
        },
        get friendlyName() {
            var attr = this.getAttribute("1.2.840.113549.1.9.20");
            if (attr === null)
                return null;
            var asn = new trusted.ASN(attr.values[0]);
            return asn.toObject("BMP_STRING");
        },
        get localKeyId() {
            var attr = this.getAttribute("1.2.840.113549.1.9.21");
            if (attr === null)
                return null;
            var asn = new trusted.ASN(attr.values[0]);
            return asn.toObject("OCTET_STRING").toString("hex");
        },
        get value() {
            if (this.type === "Unknown type")
                throw "SafeBag: Unknoun type.";
            var s = this.type.charAt(0).toUpperCase() + this.type.substring(1);
            var v = (new trusted.ASN(this.content)).toObject(s);
            switch (this.type) {
                case "certBag":
                    switch (v.certId) {
                        case "1.2.840.113549.1.9.22.1":
                            var asn = new trusted.ASN(v.certValue);
                            return new trusted.PKI.Certificate(asn.toObject("OCTET_STRING"));
                        case "1.2.840.113549.1.9.22.1":
                            var asn = new trusted.ASN(v.certValue);
                            return new trusted.PKI.Certificate(new trusted.Buffer(asn.toObject("IA5_STRING"), "base64"));
                        default:
                            throw "SafeBag.value.CertBag: Unknown certId";
                    }
                case "pkcs8ShroudedKeyBag":
                    return new trusted.PKI.EncryptedPrivateKey(v);
                case "keyBag":
                    return new trusted.PKI.PrivateKeyInfo(v);
                default:
                    throw "SafeBag.value: " + this.type + " is not suppurted";
            }
        },
        get type() {
            var oid = this.id.value;
            for (var k in SafeBagType) {
                if (SafeBagType[k] === oid)
                    return k;
            }
            return "Unknown type";
        }
    };

    this.getAttribute = function(oid) {
        if (trusted.isString(oid))
            oid = new trusted.PKI.OID(oid);
        var attrs = this.attributes;
        for (var i in attrs) {
            if (attrs[i].type.value === oid.value)
                return attrs[i];
        }
        return null;
    };

    this.toObject = function() {
        return _obj;
    };

    function init(args) {
        _obj = objFromBuffer(args[0], "SafeBag");
    }

    init.call(this, arguments);
}

var SafeBagType = {
    "keyBag": "1.2.840.113549.1.12.10.1.1",
    "pkcs8ShroudedKeyBag": "1.2.840.113549.1.12.10.1.2",
    "certBag": "1.2.840.113549.1.12.10.1.3",
    "crlBag": "1.2.840.113549.1.12.10.1.4",
    "secretBag": "1.2.840.113549.1.12.10.1.5",
    "safeContentsBag": "1.2.840.113549.1.12.10.1.6"
};

SafeBag.createCertBag = function(cert, localKeyId) {
    if (cert.type !== "Certificate")
        throw "SafeBag.createCertBag: Parameter must be type of Certificate.";
    var cb = {
        certId: "1.2.840.113549.1.9.22.1"};
    cb.certValue = trusted.ASN.fromObject(cert.export(), "OCTET_STRING").blob();
    var blob = trusted.ASN.fromObject(cb, "CertBag").blob();

    var sb = {
        bagId: "1.2.840.113549.1.12.10.1.3",
        bagValue: blob
    };
    sb.bagAttributes = [];
    if (localKeyId !== undefined) {
        if (trusted.isString(localKeyId))
            localKeyId = new trusted.Buffer(localKeyId, "utf8");
        var a = new trusted.PKI.Attribute(trusted.PKI.Attribute.create("1.2.840.113549.1.9.21", localKeyId, "OCTET_STRING"));
        sb.bagAttributes.push(a.toObject());
    }
    return trusted.ASN.fromObject(sb, "SafeBag").blob();
};

SafeBag.createKeyBag = function(key, localKeyId, friendlyName) {
    if (key.type !== "PrivateKey")
        throw "SafeBag.createCertBag: Parameter must be type of Certificate.";
    var kb = key.export();

    var sb = {
        bagId: "1.2.840.113549.1.12.10.1.1",
        bagValue: kb
    };
    sb.bagAttributes = [];
    // create friendlyName
    if (friendlyName !== undefined) {
        if (trusted.isString(friendlyName))
            friendlyName = new trusted.Buffer(friendlyName, "utf8");
        var a = new trusted.PKI.Attribute(trusted.PKI.Attribute.create("1.2.840.113549.1.9.20", friendlyName, "OCTET_STRING"));
        sb.bagAttributes.push(a.toObject());
    }
    // create localKeyId
    if (localKeyId !== undefined) {
        if (trusted.isString(localKeyId))
            localKeyId = new trusted.Buffer(localKeyId, "utf8");
        var a = new trusted.PKI.Attribute(trusted.PKI.Attribute.create("1.2.840.113549.1.9.21", localKeyId, "OCTET_STRING"));
        sb.bagAttributes.push(a.toObject());
    }

    return trusted.ASN.fromObject(sb, "SafeBag").blob();
};

SafeBag.createShroudedKeyBag = function(key, pass, localKeyId, friendlyName) {
    if (key.type !== "PrivateKey")
        throw "SafeBag.createCertBag: Parameter must be type of Certificate.";
    var pki = new trusted.PKI.PrivateKeyInfo(key.export());
    
    var ekb = trusted.PKI.EncryptedPrivateKey.create(pki.algorithm, pass,pki.content);

    var sb = {
        bagId: "1.2.840.113549.1.12.10.1.2",
        bagValue: ekb
    };
    sb.bagAttributes = [];
    // create friendlyName
    if (friendlyName !== undefined) {
        if (trusted.isString(friendlyName))
            friendlyName = new trusted.Buffer(friendlyName, "utf8");
        var a = new trusted.PKI.Attribute(trusted.PKI.Attribute.create("1.2.840.113549.1.9.20", friendlyName, "OCTET_STRING"));
        sb.bagAttributes.push(a.toObject());
    }
    // create localKeyId
    if (localKeyId !== undefined) {
        if (trusted.isString(localKeyId))
            localKeyId = new trusted.Buffer(localKeyId, "utf8");
        var a = new trusted.PKI.Attribute(trusted.PKI.Attribute.create("1.2.840.113549.1.9.21", localKeyId, "OCTET_STRING"));
        sb.bagAttributes.push(a.toObject());
    }

    return trusted.ASN.fromObject(sb, "SafeBag").blob();
};

trusted.CMS.SafeBag = SafeBag;
trusted.CMS.PFX = PFX;
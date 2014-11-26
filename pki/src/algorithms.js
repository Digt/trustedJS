/*
 * List of algorithms. It has WebCryto and OpenSSL algorithms
 * u: Usage:
 *    e: encrypt,
 *    d: dycrypt,
 *    s: sign,
 *    v: verify,
 *    dg: digest,
 *    gk: generate key,
 *    ik: import key,
 *    ek: export key,
 *    dk: derive key,
 *    db: derive bits,
 *    wk: wrap key,
 *    unwk: unwrap key
 * o: OID
 * n: name
 *   f: friendly name
 *   wc: WebCrypto
 *   nj: NodeJS 
 */

trusted.Algorithms = {
    //SHA
    "sha1": {u: ["dg"], o: "1.3.14.3.2.26", n: {f: "SHA1", wc: "sha-1", njs: "sha1"}},
    "sha224": {u: ["dg"], o: "2.16.840.1.101.3.4.2.4", n: {f: "SHA224", njs: "sha224"}},
    "sha256": {u: ["dg"], o: "2.16.840.1.101.3.4.2.1", n: {f: "SHA256", wc: "sha-256", njs: "sha256"}},
    "sha384": {u: ["dg"], o: "2.16.840.1.101.3.4.2.2", n: {f: "SHA384", wc: "sha-384", njs: "sha384"}},
    "sha512": {u: ["dg"], o: "2.16.840.1.101.3.4.2.3", n: {f: "SHA512", wc: "sha-512", njs: "sha512"}},
    //MD
    "md4": {u: ["dg"], o: "1.2.840.113549.2.4", n: {f: "MD4", njs: "md4"}},
    "md5": {u: ["dg"], o: "1.2.840.113549.2.5", n: {f: "MD5", njs: "md5"}},
    //RSA
    "rsa": {u: ["e", "d", "gk", "ik", "ek", "wk", "unwk"], o: "1.2.840.113549.1.1.1", n: {f: "RSA", njs: "rsa", wc: "RSAES-PKCS1-v1_5"}},
    "rsaencryption": "rsa",
    "rsa-md4": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.3", h: "md4", n: {f: "RSA-MD4", njs: "RSA-MD4"}},
    "rsa-md5": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.4", h: "md5", n: {f: "RSA-MD5", njs: "RSA-MD5"}},
    "rsa-sha1": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.5", h: "sha1", n: {f: "RSA-SHA1", njs: "RSA-SHA1", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-oaep": {u: ["e", "d", "gk", "ik", "ek", "wk", "unwk"], o: "1.2.840.113549.1.1.7", n: {f: "RSA-OAEP", njs: "rsaOAEP", wc: "RSA-OAEP"}},
    "rsaoaep": "rsa-oaep",
    "rsa-sha256": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.11", h: "sha256", n: {f: "RSA-SHA256", njs: "RSA-SHA256", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-sha384": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.12", h: "sha384", n: {f: "RSA-SHA384", njs: "RSA-SHA384", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-sha512": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.13", h: "sha512", n: {f: "RSA-SHA512", njs: "RSA-SHA512", wc: "RSASSA-PKCS1-v1_5"}},
    "rsa-sha224": {u: ["s", "v", "dg", "gk", "ik", "ek"], o: "1.2.840.113549.1.1.14", h: "sha224", n: {f: "RSA-SHA224", njs: "RSA-SHA224"}},
    "rsa-pss": {u: ["gk", "ik", "ek"], o: "1.2.840.113549.1.1.10", n: {f: "RSA-PSS", njs: "rsaPSS", wc: "RSA-PSS"}},
    //AES
    //AES-CBC
    "aes128-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "2.16.840.1.101.3.4.1.2", n: {f: "AES128-CBC", njs: "aes-128-cbc", wc: "aes-cbc"}},
    "aes128":"aes128-cbc",
    "aes192-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "2.16.840.1.101.3.4.1.22", n: {f: "AES192-CBC", njs: "aes-192-cbc", wc: "aes-cbc"}},
    "aes192":"aes192-cbc",
    "aes256-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "2.16.840.1.101.3.4.1.42", n: {f: "AES256-CBC", njs: "aes-256-cbc", wc: "aes-cbc"}},
    "aes256":"aes256-cbc",
    //RC2
    "rc2-cbc": {u: ["e","d","wk","unwk","gk", "ik", "ek"], o: "1.2.840.113549.3.2", n: {f: "RC2-CBC", njs: "rc2-cbc"}},
    "rc2": "rc2-cbc"
};

trusted.AlgorithmUsage = {
    encrypt: "e",
    decrypt: "d",
    sign: "s",
    verify: "v",
    digest: "dg",
    generateKey: "gk",
    importKey: "ik",
    exportKey: "ek",
    deriveKey: "dk",
    deriveBits: "db",
    wrapKey: "wk",
    unwrapKey: "unwk"
};

trusted.Algorithms.select = function(usage) {
    var err_t = "Algorithms.getAlgorithms: ";
    if (usage !== undefined) {
        if (!trusted.isArray(usage))
            usage = [usage];
        for (var i = 0; i < usage.length; i++) {
            if (!trusted.isString(usage[i]))
                throw err_t + "Parameter 'usage' has wrong data type."
            if (!(usage[i] in trusted.AlgorithmUsage))
                throw err_t + "Parameter 'usage' uses unknown algorithm usage '" + usage[i] + "'."
        }
    }

    var algs = [];
    var type = trusted.Crypto.type;
    switch (type) {
        case "webcrypto":
            type = "wc";
            break;
        case "nodejs":
            type = "njs";
            break;
        default:
            throw err_t + "Unknown trusted.Crypto type"
    }
    trusted.objEach(trusted.Algorithms, function(v, n) {
        if ((typeof (v) === "function"))
            return;
        if (trusted.isString(v))
            return;
        if (usage === undefined) {
            if (type in v.n)
                algs.push(trusted.Algorithms.getAlgorithm(n).n.f);
        }
        else {
            for (var i = 0; i < usage.length; i++) {
                if (type in v.n) {
                    if (v.u.indexOf(trusted.AlgorithmUsage[usage[i]]) > -1) {
                        algs.push(trusted.Algorithms.getAlgorithm(n).n.f);
                        break;
                    }
                }
            }
        }
    });
    return algs;
};

trusted.Algorithms.getAlgorithm = function(name) {
    var err_t = "Algorithms.getAlgorithm: ";
    if (name === undefined)
        throw err_t + "Parameter 'name' can't be undefined"
    if (!trusted.isString(name))
        throw err_t + "Parameter 'name' must be String"
    name = name.toLowerCase();
    if (!(name in trusted.Algorithms))
        throw err_t + "'" + name + "' is unknown algorithm name";
    var type = trusted.Crypto.type;
    switch (type) {
        case "webcrypto":
            type = "wc";
            break;
        case "nodejs":
            type = "njs";
            break;
        default:
            throw err_t + "Unknown trusted.Crypto type"
    }
    var alg = trusted.Algorithms[name];
    if (trusted.isString(alg))
        alg = trusted.Algorithms.getAlgorithm(alg);
    if (!(type in alg.n))
        throw err_t+"Algorithm '"+name+"' is not supported"
    if ("h" in alg && !trusted.isObject(alg.h)) {
        alg.h = trusted.Algorithms.getAlgorithm(alg.h);
    }
    return alg;
};
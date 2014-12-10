trusted.schemas.PKCS8 = {
    type: "SEQUENCE",
    value: {
        version: {type: "Version", index: 0},
        algorithm: {type: "AlgorithmIdentifier", index: 1},
        key: {type: "OCTET_STRING", index: 2}
    }
};

trusted.schemas.PrivateKeyInfo = {
    type: "SEQUENCE",
    value: {
        version: {type: "Version", index: 0},
        privateKeyAlgorithm: {type: "PrivateKeyAlgorithmIdentifier", index: 1},
        privateKey: {type: "PrivateKey", index: 2},
        attributes: {type: "Attributes", optional: true, implicit: true, context: 0, index: 3}
    }
};

trusted.schemas.PrivateKeyAlgorithmIdentifier = {
    type: "AlgorithmIdentifier"
};

trusted.schemas.PrivateKey = {type: "OCTET_STRING"};

trusted.schemas.EncryptedPrivateKeyInfo = {
    type: "SEQUENCE",
    value: {
        encryptionAlgorithm: {type: "EncryptionAlgorithmIdentifier", index: 0},
        encryptedData: {type: "PKCS8EncryptedData", index: 1} // rfc EncryptedData (conflict with EncryptedData of pkcs7)
    }
};

trusted.schemas.EncryptionAlgorithmIdentifier = {
    type: "AlgorithmIdentifier"
};

trusted.schemas.PKCS8EncryptedData = { // rfc EncryptedData (conflict with EncryptedData of pkcs7)
    type: "OCTET_STRING"
};

trusted.schemas.PKCS8 = {
    type: "SEQUENCE",
    value: {
        version: {type: "Version", index:0},
        algorithm: {type: "AlgorithmIdentifier", index:1},
        key: {type: "OCTET_STRING", index:2}
    }
};

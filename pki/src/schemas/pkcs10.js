trusted.schemas.CertificationRequest = {
    type: "SEQUENCE",
    value: {
        certificationRequestInfo: {type: "CertificationRequestInfo", index: 0},
        signatureAlgorithm: {type: "AlgorithmIdentifier", index: 1},
        signature: {type: "BIT_STRING", index: 2}
    }
};

trusted.schemas.CertificationRequestInfo = {
    type: "SEQUENCE",
    value: {
        version: {type: "INTEGER", index: 0},
        subject: {type: "Name", index: 1},
        subjectPKInfo: {type: "SubjectPublicKeyInfo", index: 2},
        attributes: {type: "Attributes", context: 0, index: 3}
    }
};

trusted.schemas.Attributes = {
    type: "SET",
    maxOccurs: MAX,
    value:{
        v: {type:"Attribute"}
    }
};

trusted.schemas.Attribute = {
    type: "SEQUENCE",
    value: {
        type: {type: "OBJECT_IDENTIFIER", index: 0},
        values: {type: "SET", minOccurs: 1, maxOccurs: MAX, value: {v:{type: "ANY"}}, index: 1}
    }
};




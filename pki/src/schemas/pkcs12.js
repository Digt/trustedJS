trusted.schemas.PFX = {
    type: "SEQUENCE",
    value: {
        version: {type: "INTEGER", index: 0}, // {v3(3)}(v3,...),
        authSafe: {type: "ContentInfo", index: 1},
        macData: {type: "MacData", optional: true, index: 2}
    }

};

trusted.schemas.MacData = {
    type: "SEQUENCE",
    value: {
        mac: {type: "DigestInfo", index: 0},
        macSalt: {type: "OCTET_STRING", index: 1},
        iterations: {type: "INTEGER", default: 1, index: 2}
    }
};

trusted.schemas.AuthenticatedSafe = {
    type: "SEQUENCE",
    maxOccurs: trusted.MAX,
    value: {
        v: {type: "ContentInfo"}
    }
};
//-- Data if unencrypted
//-- EncryptedData if password-encrypted
//-- EnvelopedData if public key-encrypted

trusted.schemas.SafeContents = {
    type: "SEQUENCE",
    maxOccurs: trusted.MAX,
    value: {
        v: {type: "SafeBag"}
    }
};


trusted.schemas.SafeBag = {
    type: "SEQUENCE",
    value: {
        bagId: {type: "OBJECT_IDENTIFIER", index: 0},
        bagValue: {type: "ANY", context: 0, explicit: true, index: 1},
        bagAttributes: {type: "SET", maxOccurs: trusted.MAX, optional: true, value: {value: {type: "Attribute"}}, index: 2}
    }

};

trusted.schemas.CertBag = {
    type: "SEQUENCE",
    value: {
        certId: {type: "OBJECT_IDENTIFIER", index: 0},
        certValue: {context: 0, type: "ANY", explicit: true, index: 1}
    }
};

trusted.schemas.KeyBag = {type:"PrivateKeyInfo"};

trusted.schemas.Pkcs8ShroudedKeyBag = { //rfc name PKCS8ShroudedKeyBag
    type: "EncryptedPrivateKeyInfo"
};

trusted.schemas.PBEParams = {
    type: "SEQUENCE",
    value: {
        salt: {type: "OCTET_STRING", index: 0},
        iterations: {type: "INTEGER", optional: true, index: 1}// (0..4294967295) OPTIONAL
    }
};

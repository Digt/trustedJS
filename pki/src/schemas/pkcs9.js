trusted.schemas.PKCS9String = {
    type: "CHOICE",
    value: {
        ia5String: {type: "IA5_STRING"}, //(SIZE(1..maxSize)),
        directoryString: {type: "DirectoryString"} //{maxSize}
    }
};

// Challenge password 1.2.840.113549.1.9.7
trusted.schemas.ChallengePassword = {
    type: "DirectoryString"
};
// Unstructured Name 1.2.840.113549.1.9.2
trusted.schemas.UnstructuredName = {
    type: "PKCS9String"
};

// Extension request 1.3.6.1.4.1.311.2.1.14
trusted.schemas.ExtensionRequest= {
    type: "Extensions"
};


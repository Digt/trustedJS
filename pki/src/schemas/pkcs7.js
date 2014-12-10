if (window.trusted === undefined)
    window.trusted = {};
if (window.trusted.schemas === undefined)
    window.trusted.schemas = {};

(function(namespace) {
    namespace.ContentInfo = {
        type: "SEQUENCE",
        value: {
            contentType: {type: "ContentType", index: 0},
            content: {type: "ANY", optional: true, context: 0}
        }
    };

    namespace.ContentType = {
        type: "OBJECT_IDENTIFIER"
    };

    /*
     data OBJECT IDENTIFIER :: = { pkcs - 7 1 }
     signedData OBJECT IDENTIFIER :: = { pkcs - 7 2 }
     envelopedData OBJECT IDENTIFIER :: = { pkcs - 7 3 }
     signedAndEnvelopedData OBJECT IDENTIFIER :: = { pkcs - 7 4 }
     digestedData OBJECT IDENTIFIER :: = { pkcs - 7 5 }
     encryptedData OBJECT IDENTIFIER :: = { pkcs - 7 6 }
     */

    namespace.Data = {
        type: "OCTET_STRING"
    };

    namespace.SignedData = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            digestAlgorithms: {type: "DigestAlgorithmIdentifiers", index: 1},
            contentInfo: {type: "ContentInfo", index: 2},
            certificates: {type: "ExtendedCertificatesAndCertificates", context: 0, implicit: true, index: 3, optional: true},
            crls: {type: "CertificateRevocationLists", context: 1, implicit: true, index: 4, optional: true},
            signerInfos: {type: "SignerInfos", index: 5}
        }
    };

    namespace.DigestEncryptionAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };

    namespace.DigestAlgorithmIdentifiers = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            digestAlgorithmIdentifier: {type: "DigestAlgorithmIdentifier"}
        }
    };

    namespace.DigestAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };

    namespace.SignerInfos = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            signerInfo: {type: "SignerInfo"}
        }
    };

    namespace.SignerInfo = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            issuerAndSerialNumber: {type: "IssuerAndSerialNumber", index: 1},
            digestAlgorithm: {type: "DigestAlgorithmIdentifier", index: 2},
            authenticatedAttributes: {type: "Attributes", context: 0, implicit: true, index: 3, optional: true},
            digestEncryptionAlgorithm: {type: "DigestEncryptionAlgorithmIdentifier", index: 4},
            encryptedDigest: {type: "EncryptedDigest", index: 5},
            unauthenticatedAttributes: {type: "Attributes", context: 1, implicit: true, index: 6, optional: true}
        }
    };

    namespace.EncryptedDigest = {
        type: "OCTET_STRING"
    };

    namespace.ContentInfo = {
        type: "SEQUENCE",
        value: {
            contentType: {type: "ContentType", index: 0},
            content: {type: "ANY", explicit: true, context: 0, optional: true, index: 1}
        }
    };

    namespace.ContentType = {
        type: "OBJECT_IDENTIFIER"
    };

    namespace.ExtendedCertificatesAndCertificates = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            extendedCertificateOrCertificate: {type: "ExtendedCertificateOrCertificate"}
        }
    };

    namespace.IssuerAndSerialNumber = {
        type: "SEQUENCE",
        value: {
            issuer: {type: "Name", index: 0},
            serialNumber: {type: "CertificateSerialNumber", index: 1}
        }
    };

    namespace.ExtendedCertificateOrCertificate = {
        type: "CHOICE",
        value: {
            certificate: {type: "ANY"}, // X.509  - Certificate / + ANY
            extendedCertificate: {type: "ExtendedCertificate", context: 0, implicit: true}  // rfc5652
        }
    };

    namespace.ExtendedCertificate = {
        type: "SEQUENCE",
        value: {
            extendedCertificateInfo: {type: "ExtendedCertificateInfo", index: 0},
            signatureAlgorithm: {type: "SignatureAlgorithmIdentifier", index: 1},
            signature: {type: "Signature", index: 2}
        }
    };

    namespace.ExtendedCertificateInfo = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version"},
            certificate: {type: "Certificate"},
            attributes: {type: "Attributes"}
        }
    };

    namespace.SignatureAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };

    namespace.Signature = {
        type: "BIT_STRING"
    };

    namespace.CertificateRevocationLists = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "CertificateRevocationList"}
        }
    };

    namespace.CertificateRevocationList = {
        type: "SEQUENCE",
        value: {
            signature: {type: "AlgorithmIdentifier", index: 0},
            issuer: {type: "Name", index: 1},
            lastUpdate: {type: "UTC_TIME", index: 2},
            nextUpdate: {type: "UTC_TIME", index: 3},
            revokedCertificates: {
                type: "SEQUENCE",
                maxOccurs: trusted.MAX,
                optional: true,
                index: 4,
                value: {
                    v: {type: "CRLEntry"}
                }
            }
        }
    };

    namespace.CRLEntry = {
        type: "SEQUENCE",
        value: {
            userCertificate: {type: "CertificateSerialNumber", index: 0},
            revocationDate: {type: "UTC_TIME", index: 1}
        }
    };

    // SigneDataContent
    namespace.DataContent = {
        type: "OCTET_STRING",
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "OCTET_STRING"}
        }
    };

    namespace.DigestInfo = {
        type: "SEQUENCE",
        value: {
            digestAlgorithm: {type: "DigestAlgorithmIdentifier", index: 0},
            digest: {type: "Digest", index: 1}
        }
    };

    namespace.Digest = {type: "OCTET_STRING"};

    //EncryptedData
    namespace.EncryptedData = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            encryptedContentInfo: {type: "EncryptedContentInfo", index: 1}
        }
    };

    namespace.EncryptedContentInfo = {
        type: "SEQUENCE",
        value: {
            contentType: {type: "ContentType", index: 0},
            contentEncryptionAlgorithm: {type: "ContentEncryptionAlgorithmIdentifier", index: 1},
            encryptedContent: {type: "EncryptedContent", context: 0, implicit: true, optional: true, index: 2}
        }
    };

    namespace.EncryptedContent = {type: "OCTET_STRING"};

    namespace.ContentEncryptionAlgorithmIdentifier = {type: "AlgorithmIdentifier"};

    namespace.EnvelopedData = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            recipientInfos: {type: "RecipientInfos", index: 1},
            encryptedContentInfo: {type: "EncryptedContentInfo", index: 2}
        }
    };

    namespace.RecipientInfos = {
        type: "SET",
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "RecipientInfo"}}
    };

    namespace.RecipientInfo = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", index: 0},
            issuerAndSerialNumber: {type: "IssuerAndSerialNumber", index: 1},
            keyEncryptionAlgorithm: {type: "KeyEncryptionAlgorithmIdentifier", index: 2},
            encryptedKey: {type: "EncryptedKey", index: 3}
        }
    };

    namespace.EncryptedKey = {type: "OCTET_STRING"};

    namespace.KeyEncryptionAlgorithmIdentifier = {
        type: "AlgorithmIdentifier"
    };


})(window.trusted.schemas);
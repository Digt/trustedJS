if (window.trusted.schemas === undefined)
    window.trusted.schemas = {};
(function(namespace) {

    namespace.Certificate = {
        type: "SEQUENCE",
        value: {
            tbsCertificate: {type: "TBSCertificate", index: 0},
            signatureAlgorithm: {type: "AlgorithmIdentifier", index: 1},
            signature: {type: "BIT_STRING", index: 2}
        }
    };
    namespace.TBSCertificate = {
        type: "SEQUENCE",
        value: {
            version: {index: 0, type: "Version", optional: true, context: 0, default: 0, explicit: true},
            serialNumber: {index: 1, type: "CertificateSerialNumber"},
            signature: {index: 2, type: "AlgorithmIdentifier"},
            issuer: {index: 3, type: "Name"},
            validity: {index: 4, type: "Validity"},
            subject: {index: 5, type: "Name"},
            subjectPublicKeyInfo: {index: 6, type: "SubjectPublicKeyInfo"},
            issuerUniqueID: {index: 7, optional: true, implicit: true, type: "UniqueIdentifier", context: 1},
            subjectUniqueID: {index: 8, optional: true, implicit: true, type: "UniqueIdentifier", context: 2},
            extensions: {index: 9, optional: true, context: 3, type: "Extensions", explicit: true}
        }
    };
    namespace.Version = {
        type: "INTEGER"
    };
    namespace.CertificateSerialNumber = {
        type: "INTEGER"
    };
    namespace.Validity = {
        type: "SEQUENCE",
        value: {
            notBefore: {index: 0, type: "Time"},
            notAfter: {index: 1, type: "Time"}
        }
    };
    namespace.Time = {
        type: "CHOICE",
        value: {
            utcTime: {type: "UTC_TIME"},
            generalTime: {type: "GENERALIZED_TIME"}
        }
    };
    namespace.UniqueIdentifier = {
        type: "BIT_STRING"
    };
    namespace.SubjectPublicKeyInfo = {
        type: "SEQUENCE",
        value: {
            algorithm: {index: 0, type: "AlgorithmIdentifier"},
            subjectPublicKey: {index: 1, type: "BIT_STRING"}
        }
    };
    namespace.Extensions = {
        type: "SEQUENCE",
        minOccurs: 0,
        maxOccurs: trusted.MAX,
        value: {
            extension: {type: "Extension"}
        }
    };
    namespace.Extension = {
        type: "SEQUENCE",
        value: {
            extnID: {index: 0, type: "OBJECT_IDENTIFIER"},
            critical: {index: 1, type: "BOOLEAN", default: false},
            extnValue: {index: 2, type: "OCTET_STRING"}
        }
    };

    namespace.AlgorithmIdentifier = {
        type: "SEQUENCE",
        value: {
            algorithm: {index: 0, type: "OBJECT_IDENTIFIER"},
            parameters: {index: 1, type: "ANY", optional: true}
        }
    };
    namespace.Name = {
        type: "CHOICE",
        value: {
            rdnSequence: {type: "RDNSequence"}
        }
    };
    namespace.RDNSequence = {
        type: "SEQUENCE",
        maxOccurs: trusted.MAX,
        value: {
            rdn: {type: "RelativeDistinguishedName"}
        }
    };
    namespace.RelativeDistinguishedName = {
        type: "SET",
        minOccurs: 0,
        maxOccurs: trusted.MAX,
        value: {
            attribute: {type: "AttributeTypeAndValue"}
        }
    };
    namespace.AttributeTypeAndValue = {
        type: "SEQUENCE",
        value: {
            type: {type: "AttributeType"},
            value: {type: "AttributeValue"}
        }
    };
    namespace.AttributeType = {
        type: "OBJECT_IDENTIFIER"
    };
    namespace.AttributeValue = {
        type: "ANY" //-- DEFINED BY AttributeType
    };
    namespace.DirectoryString = {
        type: "CHOICE",
        value: {
            teletexString: {type: "T61_STRING"}, // SIZE (1..trusted.MAX)
            printableString: {type: "PRINTABLE_STRING"}, // SIZE (1..trusted.MAX)
            universalString: {type: "UNIVERSAL_STRING"}, // SIZE (1..trusted.MAX)
            utf8String: {type: "UTF8_STRING"}, // SIZE (1..trusted.MAX)
            bmpString: {type: "BMP_STRING"} // SIZE (1..trusted.MAX)
        }
    };

    namespace.GeneralNames = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            generalName: {type: "GeneralName"}
        }
    };

    namespace.GeneralName = {
        type: "CHOICE",
        value: {
            otherName: {type: "OtherName", context: 0},
            rfc822Name: {type: "IA5_STRING", context: 1},
            dNSName: {type: "IA5_STRING", context: 2},
            //x400Address: {type: "ORAddress", context: 3},
            directoryName: {type: "Name", context: 4},
            //ediPartyName: {type: "EDIPartyName", context: 5},
            uniformResourceIdentifier: {type: "IA5_STRING", context: 6},
            iPAddress: {type: "OCTET_STRING", context: 7},
            registeredID: {type: "OBJECT_IDENTIFIER", context: 8}
        }
    };

    namespace.OtherName = {
        type: "SEQUENCE",
        value: {
            typeId: {type: "OBJECT_IDENTIFIER", index: 0},
            value: {type: "ANY", context: 0, explicit: true, index: 1}
        }
    };

    namespace.EDIPartyName = {
        type: "SEQUENCE",
        value: {
            nameAssigner: {type: "DirectoryString", context: 0, optional: true},
            partyName: {type: "DirectoryString", context: 1}
        }
    };

    // Certificate Extensions
    // 2.5.29.1
    namespace.AuthorityKeyIdentifier1 = {
        type: "SEQUENCE",
        value: {
            keyIdentifier: {type: "KeyIdentifier", optional: true, context: 0, index: 0},
            authorityCertIssuer: {type: "Name", optional: true, context: 1, index: 1},
            authorityCertSerialNumber: {type: "CertificateSerialNumber", optional: true, context: 2, index: 2}
        }
    };
    // 2.5.29.35
    namespace.AuthorityKeyIdentifier2 = {
        type: "SEQUENCE",
        value: {
            keyIdentifier: {type: "KeyIdentifier", context: 0, optional: true, index: 0},
            authorityCertIssuer: {type: "GeneralNames", optional: true, context: 1, index: 1},
            authorityCertSerialNumber: {type: "CertificateSerialNumber", optional: true, context: 2, index: 2}
        }
    };

    namespace.KeyIdentifier = {
        type: "OCTET_STRING"
    };

    namespace.KeyUsage = {
        type: "BIT_STRING"
    };

    namespace.BasicConstraints = {
        type: "SEQUENCE",
        value: {
            cA: {type: "BOOLEAN", default: false},
            pathLenConstraint: {type: "INTEGER", optional: true} // (0..trusted.MAX)
        }
    };

    namespace.IssuerSignTool = {
        type: "SEQUENCE",
        value: {
            signTool: {type: "UTF8_STRING"}, //SIZE(1.200),
            cATool: {type: "UTF8_STRING"}, // SIZE(1..200),
            signToolCert: {type: "UTF8_STRING"}, //SIZE(1.. 100),
            cAToolCert: {type: "UTF8_STRING"} //SIZE(1.100) 
        }
    };
    namespace.SubjectSignTool = {
        type: "UTF8_STRING" //SIZE(1.200)
    };

    //2.5.29.8
    namespace.IssuerAlternativeName1 = {
        type: "GeneralName"
    };
    //2.5.29.18
    namespace.IssuerAlternativeName2 = {
        type: "GeneralNames"
    };
    namespace.SubjectAlternativeName = {
        type: "GeneralNames"
    };

    namespace.SubjectKeyIdentifier = {
        type: "KeyIdentifier"
    };

    namespace.CRLDistributionPoints = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            distributionPoint: {type: "DistributionPoint"}
        }
    };

    namespace.FreshestCRL = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            distributionPoint: {
                type: "DistributionPoint"
            }
        }
    };

    namespace.DistributionPoint = {
        type: "SEQUENCE",
        value: {
            distributionPoint: {type: "DistributionPointName", optional: true, context: 0},
            reasons: {type: "ReasonFlags", optional: true, context: 1},
            cRLIssuer: {type: "GeneralNames", optional: true, context: 2}
        }
    };

    namespace.DistributionPointName = {
        type: "CHOICE",
        value: {
            fullName: {type: "GeneralNames", context: 0},
            nameRelativeToCRLIssuer: {type: "RelativeDistinguishedName", context: 1}
        }
    };

    namespace.ReasonFlags = {
        type: "BIT_STRING"
    };

    namespace.ExtKeyUsageSyntax = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            keyPurposeId: {type: "KeyPurposeId"}
        }
    };

    namespace.KeyPurposeId = {
        type: "OBJECT_IDENTIFIER"
    };

    // CertificatPolicies 2.5.29.32
    namespace.CertificatePolicies = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            policyInformation: {type: "PolicyInformation"}
        }
    };

    namespace.PolicyInformation = {
        type: "SEQUENCE",
        value: {
            policyIdentifier: {type: "CertPolicyId", index: 0},
            policyQualifiers: {type: "PolicyQualifiers", index: 1, optional: true}
        }
    };

    namespace.PolicyQualifiers = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            policyQualifierInfo: {type: "PolicyQualifierInfo"}
        }
    };

    namespace.CertPolicyId = {type: "OBJECT_IDENTIFIER"};

    namespace.PolicyQualifierInfo = {
        type: "SEQUENCE",
        value: {
            policyQualifierId: {type: "PolicyQualifierId", index: 0},
            qualifier: {type: "ANY", index: 1}
        }
    };

    namespace.PolicyQualifierId = {type: "OBJECT_IDENTIFIER"};

    namespace.Qualifier = {
        type: "CHOICE",
        value: {
            cPSuri: {type: "CPSuri"},
            userNotice: {type: "UserNotice"}
        }
    };

    namespace.CPSuri = {type: "IA5_STRING"};

    namespace.UserNotice = {
        type: "SEQUENCE",
        value: {
            noticeRef: {type: "NoticeReference", optional: true, index: 0},
            explicitText: {type: "DisplayText", optional: true, index: 1}
        }
    };

    namespace.NoticeReference = {
        type: "SEQUENCE",
        value: {
            organization: {type: "DisplayText", index: 0},
            noticeNumbers: {type: "NoticeNumbers", index: 1}
        }
    };
    namespace.NoticeNumbers = {
        type: "SEQUENCE",
        maxOccurs: trusted.MAX,
        value: {
            val: {type: "INTEGER"}
        }
    };

    namespace.DisplayText = {
        type: "CHOICE",
        value: {
            ia5String: {type: "IA5_STRING"}, //(SIZE (1..200)),
            visibleString: {type: "ISO64_STRING"}, //(SIZE (1..200)),
            bmpString: {type: "BMP_STRING"}, //(SIZE (1..200)),
            utf8String: {type: "UTF8_STRING"}     //(SIZE (1..200)) }
        }
    };

    namespace.AuthorityInfoAccessSyntax = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "AccessDescription"}
        }
    };

    namespace.AccessDescription = {
        type: "SEQUENCE",
        value: {
            accessMethod: {type: "OBJECT_IDENTIFIER", index: 0},
            accessLocation: {type: "GeneralName", index: 1}
        }
    };

    namespace.SubjectInfoAccessSyntax = {
        type: "SEQUENCE",
        minOccurs: 1,
        maxOccurs: trusted.MAX,
        value: {
            v: {type: "AccessDescription"}
        }
    };

    namespace.PrivateKeyUsagePeriod = {
        type: "SEQUENCE",
        value: {
            notBefore: {type: "GENERALIZED_TIME", optional: true, context: 0},
            notAfter: {type: "GENERALIZED_TIME", optional: true, context: 1}
        }
    };

    // CRL

    namespace.CertificateList = {
        type: "SEQUENCE",
        value: {
            tbsCertList: {type: "TBSCertList", index: 0},
            signatureAlgorithm: {type: "AlgorithmIdentifier", index: 1},
            signatureValue: {type: "BIT_STRING", index: 2}
        }
    };
    namespace.TBSCertList = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version", optional: true, index: 0},
            signature: {type: "AlgorithmIdentifier", index: 1},
            issuer: {type: "Name", index: 2},
            thisUpdate: {type: "Time", index: 3},
            nextUpdate: {type: "Time", optional: true, index: 4},
            revokedCertificates: {type: "RevokedCertificates", index: 5, optional: true},
            crlExtensions: {type: "Extensions", context: 0, explicit: true, optional: true, index: 6}
        }

    };
    namespace.RevokedCertificates = {
        type: "SEQUENCE",
        maxOccurs: trusted.MAX,
        value: {revokedCertificate: {type: "RevokedCertificate"}}
    };

    namespace.RevokedCertificate = {
        type: "SEQUENCE",
        value: {
            userCertificate: {type: "CertificateSerialNumber", index: 0},
            revocationDate: {type: "Time", index: 1},
            crlEntryExtensions: {type: "Extensions", optional: true, index: 2}
        }
    };

    // CRL Extensions
    // CRL Number 2.5.29.20
    namespace.CRLNumber = {
        type: "INTEGER" // (0..trusted.MAX)
    };

    // Delta CRL Indicator 2.5.29.27    
    namespace.BaseCRLNumber = {
        type: "CRLNumber"
    };

    // Issuing Distribution Point 2.5.29.28
    namespace.IssuingDistributionPoint = {
        type: "SEQUENCE",
        value: {
            distributionPoint: {type: "DistributionPointName", context: 0, optional: true, index: 0},
            onlyContainsUserCerts: {type: "BOOLEAN", context: 1, default: false, index: 1},
            onlyContainsCACerts: {type: "BOOLEAN", context: 2, default: false, index: 2},
            onlySomeReasons: {type: "ReasonFlags", context: 3, optional: true},
            indirectCRL: {type: "BOOLEAN", context: 4, default: false},
            onlyContainsAttributeCerts: {type: "BOOLEAN", context: 5, default: false}
        }
    };

    // 5.3.  CRL Entry Extensions
    // Reason Code 2.5.29.21
    namespace.ReasonCode = {
        type: "ENUMERATED"
                /*
                 unspecified             (0),
                 keyCompromise           (1),
                 cACompromise            (2),
                 affiliationChanged      (3),
                 superseded              (4),
                 cessationOfOperation    (5),
                 certificateHold         (6),
                 -- value 7 is not used
                 removeFromCRL           (8),
                 privilegeWithdrawn      (9),
                 aACompromise           (10
                 */
    };

    // Invalidity Date 2.5.29.24
    namespace.InvalidityDate = {
        type: "GENERALIZED_TIME"
    };
    
    // Certificate Issuer 2.5.29.29
    namespace.CertificateIssuer = {
        type:"GeneralNames"
    };

    // Keys
    namespace.RSAPublicKey = {
        type: "SEQUENCE",
        value: {
            modulus: {type: "INTEGER", index: 0},
            publicExponent: {type: "INTEGER", index: 1}
        }
    };

    namespace.RSAPrivateKey = {
        type: "SEQUENCE",
        value: {
            version: {type: "Version"},
            modulus: {type: "INTEGER"},
            publicExponent: {type: "INTEGER"},
            privateExponent: {type: "INTEGER"},
            prime1: {type: "INTEGER"},
            prime2: {type: "INTEGER"},
            exponent1: {type: "INTEGER"},
            exponent2: {type: "INTEGER"},
            coefficient: {type: "INTEGER"}
        }
    };

    namespace.GOSTPublicKey = {
        type: "OCTET_STRING"
    };

})(window.trusted.schemas);

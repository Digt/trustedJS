QualifierInfoTest = TestCase("QualifierInfo");
QualifierInfoTest.prototype.setUp = function() {

};

{
    {
        QualifierInfoTest.prototype.test_New_1 = function() {
            assertException(function() {
                new trusted.PKI.QualifierInfo();
            });
        };
        //TEST2 OID value
        QualifierInfoTest.prototype.test_New_2 = function() {
            var der = Hex.toDer("302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379");
            var tmp = new trusted.PKI.QualifierInfo(der);
            assertEquals("1.3.6.1.5.5.7.2.1", tmp.OID.value);
            assertEquals("http://ca.skbkontur.ru/policy", tmp.CPSPointer);

        };
        //TEST3 from Object
        QualifierInfoTest.prototype.test_fromObject = function() {
            var obj = {
                qualifier: Hex.toDer("020101"),
                policyQualifierId: "1.3.6.1.5.5.7.2.1"
            };
            var tmp = new trusted.PKI.QualifierInfo(obj);
            assertEquals("1.3.6.1.5.5.7.2.1", tmp.OID.value);
            assertEquals("020101", Der.toHex(tmp.encoded));
        };
        //TEST4 to string
        QualifierInfoTest.prototype.test_toString = function() {
            var der = Hex.toDer("302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379");
            var tmp = new trusted.PKI.QualifierInfo(der);
            var str = tmp.toString();
            //assertEquals("Maybe QualifierInfo doesn't have toString method","",str);

        };

        //TEST5 from Object
        QualifierInfoTest.prototype.test_toObject = function() {
            var obj = {
                qualifier: Hex.toDer("020101"),
                policyQualifierId: "1.3.4"
            };
            var crobj = new trusted.PKI.QualifierInfo(obj);
            assertEquals("020101", Der.toHex(crobj.encoded));
            assertEquals("1.3.4", crobj.OID.value);
        };
        //TEST6 Policy Information
        QualifierInfoTest.prototype.test_PolicyInformation_new_1 = function() {
            assertException(function() {
                new trusted.PKI.PolicyInformation();
            });
        };
        //TEST7 Policy Information
        QualifierInfoTest.prototype.test_PolicyInformation_new_2 = function() {
            var der = Hex.toDer("308006072A8503030702013080302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C69637900000000");
            var dps = new trusted.PKI.PolicyInformation(der);
            var oidValue = dps.qualifiers[0].CPSPointer;
            assertEquals("http://ca.skbkontur.ru/policy", oidValue);
        };
        //TEST8 Policy Information
        QualifierInfoTest.prototype.test_PolicyInformation_toObject = function() {
            var obj = {
                policyIdentifier: "0",
                policyQualifiers: [
                    {
                        policyQualifierId: "1.3",
                        qualifier: Hex.toDer("020101")
                    },
                    {
                        policyQualifierId: "1.3",
                        qualifier: Hex.toDer("020102")
                    }
                ]
            };
            var tmp = new trusted.PKI.PolicyInformation(obj);
            assertEquals("1.3", tmp.qualifiers[0].OID.value);
            assertEquals("020101", Der.toHex(tmp.qualifiers[0].encoded));
            assertEquals("2", tmp.qualifiers.length);
        };
        //TEST9 Policy Information to strin
        QualifierInfoTest.prototype.test_PolicyInformation_toString = function() {
            //fail("Sory, but test transforming Policy Information to string doesn't created for this time! Please try later!");
        };
        //TEST10 Certificate Policies
        QualifierInfoTest.prototype.test_CertificatePilicies_new_1 = function() {
            assertException(function() {
                new trusted.PKI.CertificatePolicies();
            });
        };
        //TEST11 Certificate Policies
        QualifierInfoTest.prototype.test_CertificatePilicies_new_2 = function() {
            var der = Hex.toDer("3080308006072A8503030702013080302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C69637900000000308006072A8503030702013080302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379000000000000");
            var dps = new trusted.PKI.CertificatePolicies(der);
            //var oidValue = dps.qualifiers[0].CPSPointer;
            assertEquals("1.2.643.3.7.2.1", dps.policies[0].OID.value);
            assertEquals("http://ca.skbkontur.ru/policy", dps.policies[0].qualifiers[0].CPSPointer);
            assertEquals("PKIX policy qualifier", dps.policies[0].qualifiers[0].OID.comment);
            assertEquals("2", dps.policies.length);
            console.log(JSON.stringify(dps.toObject()));
        };
        //TEST12 Policy Information
        QualifierInfoTest.prototype.test_CertificatePilicies_fromObject = function() {
            var obj = [
                {
                    "policyIdentifier": "1.2.643.3.7.2.1", 
                    "policyQualifiers": [
                        {
                            "qualifier": "\u0016\u001dhttp://ca.skbkontur.ru/policy", 
                            "policyQualifierId": "1.3.6.1.5.5.7.2.1"
                        }, 
                        {
                            "qualifier": "\u0016\u001dhttp://ca.skbkontur.ru/policy", 
                            "policyQualifierId": "1.3.6.1.5.5.7.2.1"
                        }
                    ]
                }, 
                {
                    "policyIdentifier": "1.2.643.3.7.2.1", 
                    "policyQualifiers": [
                        {
                            "qualifier": "\u0016\u001dhttp://ca.skbkontur.ru/policy",
                            "policyQualifierId": "1.3.6.1.5.5.7.2.1"
                        }, 
                        {
                            "qualifier": "\u0016\u001dhttp://ca.skbkontur.ru/policy",
                            "policyQualifierId": "1.3.6.1.5.5.7.2.1"
                        }
                    ]
                }
            ];
            var tmp = new trusted.PKI.CertificatePolicies(obj);
            //DONT finished
            assertEquals("1.3", tmp.qualifiers[0].OID.value);
            assertEquals("020101", Der.toHex(tmp.qualifiers[0].encoded));
            assertEquals("2", tmp.qualifiers.length);
        };
    }
}
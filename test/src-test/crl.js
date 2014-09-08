CRLTest = TestCase("CRL");
CRLTest.prototype.setUp = function() {
    
};
//Тесты
{
    {
        CRLTest.prototype.test_CRL_New_1 = function() {
            assertException(function() {
                new trusted.PKI.CRL();
            });
        };
        CRLTest.prototype.test_CRL_New_2 = function() {
            var der = Hex.toDer("3082029B30820183020101300D06092A864886F70D01010505003071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032170D3134303732323132353831305A170D3135303132323132353830305A30463021020200C0170D3036313230313038343430305A300C300A0603551D1504030A0104302102020114170D3132303930343130313432325A300C300A0603551D1504030A0103A081953081923081830603551D23047C307AA175A4733071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032820126300A0603551D140403020122300D06092A864886F70D01010505000382010100A11A33A08363B2A5182DEF31C4DFE3DA4E3EC1735E78C26EC746F4BA75C0BA77F2C861BBD430C6036D4A2240558868614F2BF0F28206EDC8193AFCB7C12A7FC7D7F9CDD4088D57F02F3432DCA8A24FBDEC96C5DCAFB93ACF5536F340DE52705BCB07793B43327A0F0A30971442724B4C47A98B55F6F38433875D786B5F1B7A810531C222FD2F99745193494E20D5919F519098FB53DE818A7C33435B81B53EBA921F48263E132E14FD683AAF4052A0230083D31C66CF9E665BD9C7680D221728227439716E1B2507044BA382B43B057A419EDC33E0E02D10E36C5F006F1D7AB58BB7C7C8E36069471A8AF10BB45F1CB33201165A4640FEBF5835A55845783D1B");
            var crl = new trusted.PKI.CRL(der);
            assertEquals(2,crl.certificates.length);
            assertEquals("192",crl.certificates[0].serialNumber);
            assertEquals(2,crl.extensions.length);
            assertEquals(34,crl.sequenceNumber);
            assertEquals(4,crl.issuerName.RDNs.length);
            assertEquals("sha1WithRSAEncryption",crl.signatureAlgorithm.OID.name);
            assertEquals(new Date(2014,6,22,16,58,10),crl.thisUpdate);
            assertEquals(new Date(2015,0,22,16,58,00),crl.nextUpdate);
            
        };
        CRLTest.prototype.test_CRL_fromObject = function(){
            var obj = {
                "tbsCertLis":
                        {
                            version:1,
                            signature:
                                    {
                                        "algorithm":"2.5.4.3",
                                        "parameters":Hex.toDer("0500")
                                    },
                            issuer:
                                    {
                                        "rdnSequence":
                                        [
                                            [
                                                {
                                                    "type":"2.5.4.6",
                                                    "value":Hex.toDer("020101")
                                                }
                                            ],
                                            [
                                                {
                                                    "type":"2.5.4.10",
                                                    "value":Hex.toDer("020102")
                                                }
                                            ],
                                            [
                                                {
                                                    "type":"2.5.4.11",
                                                    "value":Hex.toDer("020103")
                                                }
                                            ],
                                            [
                                                {
                                                    "type":"2.5.4.3",
                                                    "value":Hex.toDer("020104")
                                                }
                                            ]
                                        ]
                                    },
                            thisUpdate:
                                {
                                    "generalTime":"2014-07-22T12:58:10.000Z"
                                },
                            revokedCertificates:
                                    [
                                        {
                                            "userCertificate":192,
                                            "revocationDate":
                                                    {
                                                        "generalTime":"2006-12-01T08:44:00.000Z"
                                                    },
                                            "crlEntryExtensions":
                                                    [
                                                        {
                                                            "critical":false,
                                                            "extnId":"2.5.29.21",
                                                            "extnValue":Hex.toDer("020105")
                                                        }
                                                    ]
                                        },
                                        {
                                            "userCertificate":276,
                                            "revocationDate":
                                                    {
                                                        "generalTime":"2012-09-04T10:14:22.000Z"
                                                    },
                                            "crlEntryExtensions":
                                                    [
                                                        {
                                                            "critical":false,
                                                            "extnId":"2.5.29.21",
                                                            "extnValue":Hex.toDer("020101")
                                                        }
                                                    ]
                                        }
                                    ],
                            crlExtensions:
                                    [
                                        {
                                            "critical":false,
                                            "extnId":"2.5.29.35",
                                            "extnValue":Hex.toDer("020101")
                                        },
                                        {"critical":false,
                                            "extnId":"2.5.29.20",
                                            "extnValue":Hex.toDer("020101")
                                        }
                                    ]
                        },
                    signatureAlgorithm:
                            {
                                "algorithm":{
                                    "name":"sha1WithRSAEncryption",
                                    "comment":"PKCS #1"
                                },
                                "parameters":Hex.toDer("020101")
                            },
                    signatureValue:
                            {
                                "unusedBit":0,
                                "encoded":Hex.toDer("02020301")
                            }
            };/*
            console.log("---===---");
            console.log(obj);
            console.log(JSON.stringify(obj.toObject()));*/
            var crl = new trusted.PKI.CRL(obj);
        //console.log(crl);
        };
        
        
        
        
        
        
        
//-----------------------------------------------------------------------------------------------------------------------------------------//        
        CRLTest.prototype.test_CRL_hasCertificate = function(){
            var der = Hex.toDer("3082029B30820183020101300D06092A864886F70D01010505003071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032170D3134303732323132353831305A170D3135303132323132353830305A30463021020200C0170D3036313230313038343430305A300C300A0603551D1504030A0104302102020114170D3132303930343130313432325A300C300A0603551D1504030A0103A081953081923081830603551D23047C307AA175A4733071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032820126300A0603551D140403020122300D06092A864886F70D01010505000382010100A11A33A08363B2A5182DEF31C4DFE3DA4E3EC1735E78C26EC746F4BA75C0BA77F2C861BBD430C6036D4A2240558868614F2BF0F28206EDC8193AFCB7C12A7FC7D7F9CDD4088D57F02F3432DCA8A24FBDEC96C5DCAFB93ACF5536F340DE52705BCB07793B43327A0F0A30971442724B4C47A98B55F6F38433875D786B5F1B7A810531C222FD2F99745193494E20D5919F519098FB53DE818A7C33435B81B53EBA921F48263E132E14FD683AAF4052A0230083D31C66CF9E665BD9C7680D221728227439716E1B2507044BA382B43B057A419EDC33E0E02D10E36C5F006F1D7AB58BB7C7C8E36069471A8AF10BB45F1CB33201165A4640FEBF5835A55845783D1B");
            var crl = new trusted.PKI.CRL(der);
            var cert = {
                issuerName: new trusted.PKI.Name({
                                        "rdnSequence":
                                        [
                                            [
                                                {
                                                    "type":"2.5.4.6",
                                                    "value":Hex.toDer("020101")
                                                }
                                            ],
                                            [
                                                {
                                                    "type":"2.5.4.10",
                                                    "value":Hex.toDer("020102")
                                                }
                                            ],
                                            [
                                                {
                                                    "type":"2.5.4.11",
                                                    "value":Hex.toDer("020103")
                                                }
                                            ],
                                            [
                                                {
                                                    "type":"2.5.4.3",
                                                    "value":Hex.toDer("020104")
                                                }
                                            ]
                                        ]
                                    }),
                                    serialNumber:192
            };
            assertEquals(cert.serialNumber,crl.certificates[0].serialNumber);
            assertEquals(cert.issuerName,crl.certificates[0].issuerName);//but was null
            /*
            var der1 = trusted.ASN.fromObject(cer, "Certificate").encode();
            var cert = new trusted.PKI.Certificate(der1);
            
            console.log(cert);
            
            
            assertTrue(true,crl.hasCertificate(cert));*/
        };
        CRLTest.prototype.test_getExtension = function(){
            var der = Hex.toDer("3082029B30820183020101300D06092A864886F70D01010505003071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032170D3134303732323132353831305A170D3135303132323132353830305A30463021020200C0170D3036313230313038343430305A300C300A0603551D1504030A0104302102020114170D3132303930343130313432325A300C300A0603551D1504030A0103A081953081923081830603551D23047C307AA175A4733071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032820126300A0603551D140403020122300D06092A864886F70D01010505000382010100A11A33A08363B2A5182DEF31C4DFE3DA4E3EC1735E78C26EC746F4BA75C0BA77F2C861BBD430C6036D4A2240558868614F2BF0F28206EDC8193AFCB7C12A7FC7D7F9CDD4088D57F02F3432DCA8A24FBDEC96C5DCAFB93ACF5536F340DE52705BCB07793B43327A0F0A30971442724B4C47A98B55F6F38433875D786B5F1B7A810531C222FD2F99745193494E20D5919F519098FB53DE818A7C33435B81B53EBA921F48263E132E14FD683AAF4052A0230083D31C66CF9E665BD9C7680D221728227439716E1B2507044BA382B43B057A419EDC33E0E02D10E36C5F006F1D7AB58BB7C7C8E36069471A8AF10BB45F1CB33201165A4640FEBF5835A55845783D1B");
            var crl = new trusted.PKI.CRL(der);
            assertEquals("cRLNumber",(crl.getExtension("2.5.29.20")).OID.name);
            assertEquals("2.5.29.20",(crl.getExtension("2.5.29.20")).OID.value);
            assertEquals("authorityKeyIdentifier",(crl.getExtension("2.5.29.35")).OID.name);
            assertEquals("2.5.29.35",(crl.getExtension("2.5.29.35")).OID.value);
        };
    }
}
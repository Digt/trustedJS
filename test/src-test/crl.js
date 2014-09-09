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
            assertEquals(2, crl.certificates.length);
            assertEquals("192", crl.certificates[0].serialNumber);
            assertEquals(2, crl.extensions.length);
            assertEquals(34, crl.sequenceNumber);
            assertEquals(4, crl.issuerName.RDNs.length);
            assertEquals("sha1WithRSAEncryption", crl.signatureAlgorithm.OID.name);
            assertEquals(new Date(2014, 6, 22, 16, 58, 10), crl.thisUpdate);
            assertEquals(new Date(2015, 0, 22, 16, 58, 00), crl.nextUpdate);

        };
        CRLTest.prototype.test_CRL_fromObject = function() {
            var obj = {
                "tbsCertLis":
                        {
                            version: 1,
                            signature:
                                    {
                                        "algorithm": "2.5.4.3",
                                        "parameters": Hex.toDer("0500")
                                    },
                            issuer:
                                    {
                                        "rdnSequence":
                                                [
                                                    [
                                                        {
                                                            "type": "2.5.4.6",
                                                            "value": Hex.toDer("020101")
                                                        }
                                                    ],
                                                    [
                                                        {
                                                            "type": "2.5.4.10",
                                                            "value": Hex.toDer("020102")
                                                        }
                                                    ],
                                                    [
                                                        {
                                                            "type": "2.5.4.11",
                                                            "value": Hex.toDer("020103")
                                                        }
                                                    ],
                                                    [
                                                        {
                                                            "type": "2.5.4.3",
                                                            "value": Hex.toDer("020104")
                                                        }
                                                    ]
                                                ]
                                    },
                            thisUpdate:
                                    {
                                        "generalTime": "2014-07-22T12:58:10.000Z"
                                    },
                            revokedCertificates:
                                    [
                                        {
                                            "userCertificate": 192,
                                            "revocationDate":
                                                    {
                                                        "generalTime": "2006-12-01T08:44:00.000Z"
                                                    },
                                            "crlEntryExtensions":
                                                    [
                                                        {
                                                            "critical": false,
                                                            "extnId": "2.5.29.21",
                                                            "extnValue": Hex.toDer("020105")
                                                        }
                                                    ]
                                        },
                                        {
                                            "userCertificate": 276,
                                            "revocationDate":
                                                    {
                                                        "generalTime": "2012-09-04T10:14:22.000Z"
                                                    },
                                            "crlEntryExtensions":
                                                    [
                                                        {
                                                            "critical": false,
                                                            "extnId": "2.5.29.21",
                                                            "extnValue": Hex.toDer("020101")
                                                        }
                                                    ]
                                        }
                                    ],
                            crlExtensions:
                                    [
                                        {
                                            "critical": false,
                                            "extnId": "2.5.29.35",
                                            "extnValue": Hex.toDer("020101")
                                        },
                                        {"critical": false,
                                            "extnId": "2.5.29.20",
                                            "extnValue": Hex.toDer("020101")
                                        }
                                    ]
                        },
                signatureAlgorithm:
                        {
                            "algorithm": {
                                "name": "sha1WithRSAEncryption",
                                "comment": "PKCS #1"
                            },
                            "parameters": Hex.toDer("020101")
                        },
                signatureValue:
                        {
                            "unusedBit": 0,
                            "encoded": Hex.toDer("02020301")
                        }
            };
            console.log(obj);
            var crl = new trusted.PKI.CRL(obj);
            console.log(crl);
        };
//-----------------------------------------------------------------------------------------------------------------------------------------//        
        CRLTest.prototype.test_CRL_hasCertificate = function() {
            var der = Hex.toDer("3082029B30820183020101300D06092A864886F70D01010505003071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032170D3134303732323132353831305A170D3135303132323132353830305A30463021020200C0170D3036313230313038343430305A300C300A0603551D1504030A0104302102020114170D3132303930343130313432325A300C300A0603551D1504030A0103A081953081923081830603551D23047C307AA175A4733071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032820126300A0603551D140403020122300D06092A864886F70D01010505000382010100A11A33A08363B2A5182DEF31C4DFE3DA4E3EC1735E78C26EC746F4BA75C0BA77F2C861BBD430C6036D4A2240558868614F2BF0F28206EDC8193AFCB7C12A7FC7D7F9CDD4088D57F02F3432DCA8A24FBDEC96C5DCAFB93ACF5536F340DE52705BCB07793B43327A0F0A30971442724B4C47A98B55F6F38433875D786B5F1B7A810531C222FD2F99745193494E20D5919F519098FB53DE818A7C33435B81B53EBA921F48263E132E14FD683AAF4052A0230083D31C66CF9E665BD9C7680D221728227439716E1B2507044BA382B43B057A419EDC33E0E02D10E36C5F006F1D7AB58BB7C7C8E36069471A8AF10BB45F1CB33201165A4640FEBF5835A55845783D1B");
            var crl = new trusted.PKI.CRL(der);
            var obj = {
                tbsCertificate: {
                    version: 2,
                    issuer: {
                        "rdnSequence":
                                [
                                    [
                                        {
                                            "type": "2.5.4.6",
                                            "value": crl.issuerName.RDNs[0].attributes[0].value,
                                            "text": crl.issuerName.RDNs[0].attributes[0].text
                                        }
                                    ],
                                    [
                                        {
                                            "type": "2.5.4.10",
                                            "value": crl.issuerName.RDNs[1].attributes[0].value,
                                            "text": crl.issuerName.RDNs[1].attributes[0].text
                                        }
                                    ],
                                    [
                                        {
                                            "type": "2.5.4.11",
                                            "value": crl.issuerName.RDNs[2].attributes[0].value,
                                            "text": crl.issuerName.RDNs[2].attributes[0].text
                                        }
                                    ],
                                    [
                                        {
                                            "type": "2.5.4.3",
                                            "value": crl.issuerName.RDNs[3].attributes[0].value,
                                            "text": crl.issuerName.RDNs[3].attributes[0].text
                                        }
                                    ]
                                ]
                    },
                    serialNumber: 192,
                    compare: function(cert) {
                        if (cert.issuerName === undefined && cert.serialNumber === undefined)
                            throw "Certificate.compare: Параметр имеет неверный формат."
                        return (this.issuerName.toString() === cert.issuerName.toString() &&
                                this.serialNumber === cert.serialNumber);
                    },
                    signature: {
                        algorithm: "1.2.840.113549.1.1.4",
                        parameters: Hex.toDer("0500")
                    },
                    validity: {
                        notBefore: {
                            utcTime: new Date()},
                        notAfter: {
                            utcTime: new Date()}
                    },
                    subject: {
                        rdnSequence: [
                            [{type: "2.5.4.6", value: trusted.ASN.fromObject("US", "UTF8_STRING").encode()}],
                            [{type: "2.5.4.10", value: trusted.ASN.fromObject("MSFT", "UTF8_STRING").encode()}],
                            [{type: "2.5.4.3", value: trusted.ASN.fromObject("Microsoft Authenticode(tm) Root Authority", "UTF8_STRING").encode()}]
                        ]
                    },
                    subjectPublicKeyInfo: {
                        algorithm: {
                            algorithm: "1.2.840.113549.1.1.1",
                            parameters: Hex.toDer("0500")
                        },
                        subjectPublicKey: new BitString(Hex.toDer("003082010A0282010100DF08BAE33F6E649BF589AF28964A078F1B2E8B3E1DFCB88069A3A1CEDBDFB08E6C8976294FCA603539AD7232E00BAE293D4C16D94B3C9DDAC5D3D109C92C6FA6C2605345DD4BD155CD031CD2595624F3E578D807CCD8B31F903FC01A71501D2DA712086D7CB0866CC7BA853207E1616FAF03C56DE5D6A18F36F6C10BD13E69974872C97FA4C8C24A4C7EA1D194A6D7DCEB05462EB818B4571D8649DB694A2C21F55E0F542D5A43A97A7E6A8E504D2557A1BF1B1505437B2C058DBD3D038C93227D63EA0A5705060ADB6198652D4749A8E7E656755CB8640863A9304066B2F9B6E334E86730E1430B87FFC9BE72105E23F09BA74865BF09887BCD72BC2E799B7B0203010001"), 0)
                    }
                },
                signatureAlgorithm: {
                    "algorithm": "1.2.840.113549.1.1.4",
                    parameters: Hex.toDer("0500")},
                signature: new BitString(Hex.toDer("002DC9E2F6129E5D5667FAFA4B9A7EDC29565C80140228856E26F3CD58DA5080C5F819B3A67CE29D6B5F3B8F2274E61804FC4740D87A3F3066F012A4D1EB1DE7B6F498AB5322865158EE230976E41D455C4BFF4CE302500113CC41A45297D486D5C4FE8383657DEABEA2683BC1B12998BFA2A5FC9DD384EE701750F30BFA3CEFA9278B91B448C845A0E101424B4476041CC219A28E6B2098C4DD02ACB4D2A20E8D5DB9368E4A1B5D6C1AE2CB007F10F4B295EFE3E8FFA17358A9752CA2499585FECCDA448AC21244D244C8A5A21FA95A8E56C2C37BCF4260DC821FFBCE74067ED6F1AC196A4F745CC51566316CC16271910F595B7D2A821ADFB1B4D81D37DE0D0F"), 0)
            };

            var cert = new trusted.PKI.Certificate(obj);
            assertTrue(crl.hasCertificate(cert));
            fail("THIS test has sertificate wrong logic");
        };
        CRLTest.prototype.test_getExtension = function() {
            var der = Hex.toDer("3082029B30820183020101300D06092A864886F70D01010505003071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032170D3134303732323132353831305A170D3135303132323132353830305A30463021020200C0170D3036313230313038343430305A300C300A0603551D1504030A0104302102020114170D3132303930343130313432325A300C300A0603551D1504030A0103A081953081923081830603551D23047C307AA175A4733071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032820126300A0603551D140403020122300D06092A864886F70D01010505000382010100A11A33A08363B2A5182DEF31C4DFE3DA4E3EC1735E78C26EC746F4BA75C0BA77F2C861BBD430C6036D4A2240558868614F2BF0F28206EDC8193AFCB7C12A7FC7D7F9CDD4088D57F02F3432DCA8A24FBDEC96C5DCAFB93ACF5536F340DE52705BCB07793B43327A0F0A30971442724B4C47A98B55F6F38433875D786B5F1B7A810531C222FD2F99745193494E20D5919F519098FB53DE818A7C33435B81B53EBA921F48263E132E14FD683AAF4052A0230083D31C66CF9E665BD9C7680D221728227439716E1B2507044BA382B43B057A419EDC33E0E02D10E36C5F006F1D7AB58BB7C7C8E36069471A8AF10BB45F1CB33201165A4640FEBF5835A55845783D1B");
            var crl = new trusted.PKI.CRL(der);
            assertEquals("cRLNumber", (crl.getExtension("2.5.29.20")).OID.name);
            assertEquals("2.5.29.20", (crl.getExtension("2.5.29.20")).OID.value);
            assertEquals("authorityKeyIdentifier", (crl.getExtension("2.5.29.35")).OID.name);
            assertEquals("2.5.29.35", (crl.getExtension("2.5.29.35")).OID.value);
        };
        CRLTest.prototype.test_CRL_toObject = function() {
            var der = Hex.toDer("3082029B30820183020101300D06092A864886F70D01010505003071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032170D3134303732323132353831305A170D3135303132323132353830305A30463021020200C0170D3036313230313038343430305A300C300A0603551D1504030A0104302102020114170D3132303930343130313432325A300C300A0603551D1504030A0103A081953081923081830603551D23047C307AA175A4733071310B3009060355040613024445311C301A060355040A131344657574736368652054656C656B6F6D204147311F301D060355040B1316542D54656C655365632054727573742043656E746572312330210603550403131A44657574736368652054656C656B6F6D20526F6F742043412032820126300A0603551D140403020122300D06092A864886F70D01010505000382010100A11A33A08363B2A5182DEF31C4DFE3DA4E3EC1735E78C26EC746F4BA75C0BA77F2C861BBD430C6036D4A2240558868614F2BF0F28206EDC8193AFCB7C12A7FC7D7F9CDD4088D57F02F3432DCA8A24FBDEC96C5DCAFB93ACF5536F340DE52705BCB07793B43327A0F0A30971442724B4C47A98B55F6F38433875D786B5F1B7A810531C222FD2F99745193494E20D5919F519098FB53DE818A7C33435B81B53EBA921F48263E132E14FD683AAF4052A0230083D31C66CF9E665BD9C7680D221728227439716E1B2507044BA382B43B057A419EDC33E0E02D10E36C5F006F1D7AB58BB7C7C8E36069471A8AF10BB45F1CB33201165A4640FEBF5835A55845783D1B");
            var crl = new trusted.PKI.CRL(der);
            assertNotUndefined(crl.toObject());
        };
        CRLTest.prototype.test_CRL_toString = function(){
            fail("Test CRL to string not created. Maybe the test is not necessary.");
        };
    }
}
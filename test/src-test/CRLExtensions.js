CRLTest = TestCase("CRL");
CRLTest.prototype.setUp = function() {
};
{
    {
        CRLTest.prototype.test_CRL_Extension_new1 = function() {
            assertException(function() {
                new trusted.PKI.CRL();
            });
        };
        //Create crl
        CRLTest.prototype.test_CRL_Extension_create = function() {
            var der = Hex.toDer("308202403082022C020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018830820184300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D65820701020201020201302E0603551D0804278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            assertNotUndefined(new trusted.PKI.CRL(der));
        };

        //Authority Key Identifier
        CRLTest.prototype.test_AuthorityKeyIdentifier = function() {
            var der = Hex.toDer("308202403082022C020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018830820184300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D65820701020201020201302E0603551D0804278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            var crl = new trusted.PKI.CRL(der);
            var extn = crl.getExtension("2.5.29.35");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(extn.value);
            assertEquals("283682606809601", aki.serialNumber);
            assertEquals("\u0016\u0011Some company name", aki.issuerName.generalNames[0].name.RDNs[0].attributes[0].value);
            assertEquals("Some company name", aki.issuerName.generalNames[0].name.RDNs[0].attributes[0].text);
            assertEquals("2.5.4.3", aki.issuerName.generalNames[0].name.RDNs[0].attributes[0].OID.value);
        };
        CRLTest.prototype.test_AuthorityKeyIdentifier_new_fromObject = function() {
            var str = trusted.ASN.fromObject("Some company name", "IA5_STRING").encode();
            var obj = {
                keyIdentifier: Hex.toDer("1001010110"),
                authorityCertSerialNumber: "2648086465486",
                authorityCertIssuer: [{directoryName: {rdnSequence: [[{type: "2.5.4.3", value: str}]]}}]
            };
            var aki = new trusted.PKI.AuthorityKeyIdentifier(obj);
            assertEquals("2648086465486", aki.serialNumber);
            assertEquals("\u0016\u0011Some company name", aki.issuerName.generalNames[0].name.RDNs[0].attributes[0].value);
            assertEquals("Some company name", aki.issuerName.generalNames[0].name.RDNs[0].attributes[0].text);
            assertEquals("2.5.4.3", aki.issuerName.generalNames[0].name.RDNs[0].attributes[0].OID.value);
        };
        CRLTest.prototype.test_AuthorityKeyIdentifier_toObject = function() {
            var der = Hex.toDer("302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D65820701020201020201");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(der);
            var akiObj = aki.toObject();
            assertEquals("283682606809601", akiObj.authorityCertSerialNumber);
            assertEquals("2.5.4.3", akiObj.authorityCertIssuer[0].directoryName.rdnSequence[0][0].type);
            assertEquals("\u0016\u0011Some company name", akiObj.authorityCertIssuer[0].directoryName.rdnSequence[0][0].value);
        };
        CRLTest.prototype.test_AuthorityKeyIdentifier_toString = function() {
            var der = Hex.toDer("302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D65820701020201020201");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(der);
            var akiStr = aki.toString();
            //fail("THIS WORK, but i don't know how to test this");
        };
        //end

        //Issuer Alternative Name        
        CRLTest.prototype.test_IssuerAlternativeName = function() {
            var der = Hex.toDer("308202423082022E020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018A30820186300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D6582070102020102020130300603551D12042930278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            var crl = new trusted.PKI.CRL(der);
            var extn = crl.getExtension("2.5.29.18");
            var ian = new trusted.PKI.IssuerAlternativeName(extn.value);
            var str = "http://digt.com/IssuerAlternativeName";
            assertEquals(str, ian.generalNames[0].name);
        };
        CRLTest.prototype.test_IssuerAlternativeName_fromObject = function() {
            var obj = [{dNSName: "http://digt.com/IssuerAlternativeName"}];
            var ian = new trusted.PKI.IssuerAlternativeName(obj);
            var str = "http://digt.com/IssuerAlternativeName";
            assertEquals(str, ian.generalNames[0].name);
        };
        CRLTest.prototype.test_IssuerAlternativeName_toObject = function() {
            var der = Hex.toDer("30278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65");
            var ian = new trusted.PKI.IssuerAlternativeName(der, "2.5.29.18");
            var ianObj = ian.toObject();
            assertEquals("http://digt.com/IssuerAlternativeName", ianObj[0].dNSName);
        };
        CRLTest.prototype.test_IssuerAlternativeName_toString = function() {
            var der = Hex.toDer("30278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65");
            var ian = new trusted.PKI.IssuerAlternativeName(der, "2.5.29.18");
            var ianStr = ian.toString();
            //fail ("This method is not realised");
        };
        //end

        //Base CRL Number
        CRLTest.prototype.test_BaseCRLNumber = function() {
            var der = Hex.toDer("308202423082022E020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018A30820186300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D6582070102020102020130300603551D12042930278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            var crl = new trusted.PKI.CRL(der);
            var extn = crl.getExtension("2.5.29.27");
            var bcn = new trusted.PKI.BaseCRLNumber(extn.value);
            assertEquals("333", bcn.value);
        };
        CRLTest.prototype.test_BaseCRLNumber_fromObject = function() {
            var obj = 333;
            var bcn = new trusted.PKI.BaseCRLNumber(obj);
            assertEquals("333", bcn.value);
        };
        CRLTest.prototype.test_BaseCRLNumber_toObject = function() {
            var der = Hex.toDer("020300014D");
            var bCRLn = new trusted.PKI.BaseCRLNumber(der);
            var bCRLnObj = bCRLn.toObject();
            assertEquals(333, bCRLnObj);
        };
        CRLTest.prototype.test_BaseCRLNumber_toString = function() {
            var der = Hex.toDer("020300014D");
            var bCRLn = new trusted.PKI.BaseCRLNumber(der);
            var bCRLnStr = bCRLn.toString();
            //fail ("This method is not realised");
        };
        //end

        //Issuing Distribution Point
        CRLTest.prototype.test_IssuingDistributionPoint = function() {
            var der = Hex.toDer("308202423082022E020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018A30820186300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D6582070102020102020130300603551D12042930278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            var crl = new trusted.PKI.CRL(der);
            var extn = crl.getExtension("2.5.29.28");
            var idp = new trusted.PKI.IssuingDistributionPoint(extn.value);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", idp.pointName[0].uniformResourceIdentifier);
            assertTrue(idp.indirectCRL, idp.onlyContainsUserCerts);
            assertFalse(idp.onlyContainsAttributeCerts, idp.onlyContainsCACerts);
        };
        /*Не работет т.к. onlySomeReasons: [Exception: TypeError: Cannot read property 'toNumber' of undefined]*/
        CRLTest.prototype.test_IssuingDistributionPoint_fromObject = function() {
            var obj = {
                indirectCRL: true,
                distributionPoint: {fullName: [{uniformResourceIdentifier: "http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl"}]}
            };
            var idp = new trusted.PKI.IssuingDistributionPoint(obj);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", idp.pointName[0].uniformResourceIdentifier);
            assertTrue(idp.indirectCRL);
        };
        CRLTest.prototype.test_IssuingDistributionPoint_toObject = function() {
            var der = Hex.toDer("303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C810101840101");
            var idp = new trusted.PKI.IssuingDistributionPoint(der);
            var idpObj = idp.toObject();
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", idp.pointName[0].uniformResourceIdentifier);
            assertTrue(idp.indirectCRL, idp.onlyContainsUserCerts);
            assertFalse(idp.onlyContainsAttributeCerts, idp.onlyContainsCACerts);
        };
        CRLTest.prototype.test_IssuingDistributionPoint_toString = function() {
            var der = Hex.toDer("303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C810101840101");
            var idp = new trusted.PKI.IssuingDistributionPoint(der);
            var idpStr = idp.toString();
            //fail ("This method is not realised");
        };
        //end

        //Freshest CRL
        CRLTest.prototype.test_FreshestCRL = function() {
            var der = Hex.toDer("308202423082022E020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018A30820186300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D6582070102020102020130300603551D12042930278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            var crl = new trusted.PKI.CRL(der);
            var extn = crl.getExtension("2.5.29.46");
            var frt = new trusted.PKI.FreshestCRL(extn.value);
            assertEquals("http://cdp.skbkontur.ru", frt.distributionPoints[0].CRLIssuer.generalNames[0].name);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", frt.distributionPoints[0].distributionPoint.fullName.generalNames[0].name);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", frt.distributionPoints[0].name.fullName.generalNames[0].name);
            assertEquals(2, frt.distributionPoints[0].reasons);
        };
        CRLTest.prototype.test_FreshestCRL_fromObject = function() {
            var obj =
                    [{
                            cRLIssuer: [{uniformResourceIdentifier: "http://cdp.skbkontur.ru"}],
                            distributionPoint: {fullName: [{uniformResourceIdentifier: "http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl"}]},
                            reasons: new BitString(trusted.PKI.ReasonFlags.KeyCompromise)
                        }];
            var frt = new trusted.PKI.FreshestCRL(obj);
            assertEquals("http://cdp.skbkontur.ru", frt.distributionPoints[0].CRLIssuer.generalNames[0].name);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", frt.distributionPoints[0].distributionPoint.fullName.generalNames[0].name);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", frt.distributionPoints[0].name.fullName.generalNames[0].name);
            assertEquals(2, frt.distributionPoints[0].reasons);
        };
        CRLTest.prototype.test_FreshestCRL_toObject = function() {
            var der = Hex.toDer("30563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E7275");
            var frt = new trusted.PKI.FreshestCRL(der);
            var frtObj = frt.toObject();
            assertEquals("http://cdp.skbkontur.ru", frtObj[0].cRLIssuer[0].uniformResourceIdentifier);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", frtObj[0].distributionPoint.fullName[0].uniformResourceIdentifier);
        };
        CRLTest.prototype.test_FreshestCRL_toString = function() {
            var der = Hex.toDer("30563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E7275");
            var frt = new trusted.PKI.FreshestCRL(der);
            var frtStr = frt.toString();
            //fail ("This method is not realised");
        };
        //end

        //Authority Info Access
        CRLTest.prototype.test_AuthorityInfoAccess = function() {
            var der = Hex.toDer("308202423082022E020101300706035504030500303431323030060355040613294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479180F32303134303732323136353831305A304B3023020200C0180F32303036313230313132343430305A300C300A0603551D15040302010530240203000114180F32303132303930343134313432325A300C300A0603551D150403020101A082018A30820186300C0603551D1B0405020300014D30440603551D1C043D303BA033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81010184010130380603551D230431302F80020102A120A41E301C311A301806035504031611536F6D6520636F6D70616E79206E616D6582070102020102020130300603551D12042930278225687474703A2F2F646967742E636F6D2F497373756572416C7465726E61746976654E616D65305F0603551D2E045830563054A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C81020002A2198617687474703A2F2F6364702E736B626B6F6E7475722E727530630603551D30045C305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E63727430070603551D01050003050002020301");
            var crl = new trusted.PKI.CRL(der);
            var extn = crl.getExtension("2.5.29.48");
            var aia = new trusted.PKI.AuthorityInfoAccess(extn.value);
            assertEquals("http://digit.ru/someCert.crt", aia.descriptions[0].location.name);
            assertEquals("1.3.6.2.5.4.2.40.1", aia.descriptions[0].method.value);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt", aia.descriptions[1].location.name);
            assertEquals("1.3.6.1.5.5.7.48.2", aia.descriptions[1].method.value);
        };
        CRLTest.prototype.test_AuthorityInfoAccess_fromObject = function() {
            var obj = [
                {
                    "accessLocation":
                            {
                                "uniformResourceIdentifier": "http://digit.ru/someCert.crt"
                            },
                    "accessMethod": "1.3.6.2.5.4.2.40.1"
                },
                {
                    "accessLocation":
                            {
                                "uniformResourceIdentifier": "http://rostelecom.ru/cdp/vguc1.crt"
                            },
                    "accessMethod": "1.3.6.1.5.5.7.48.2"
                }
            ];
            var aia = new trusted.PKI.AuthorityInfoAccess(obj);
            assertEquals("http://digit.ru/someCert.crt", aia.descriptions[0].location.name);
            assertEquals("1.3.6.2.5.4.2.40.1", aia.descriptions[0].method.value);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt", aia.descriptions[1].location.name);
            assertEquals("1.3.6.1.5.5.7.48.2", aia.descriptions[1].method.value);
        };
        CRLTest.prototype.test_AuthorityInfoAccess_toObject = function() {
            var der = Hex.toDer("305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274");
            var aia = new trusted.PKI.AuthorityInfoAccess(der);
            var aiaObj = aia.toObject();
            assertEquals("http://digit.ru/someCert.crt", aiaObj[0].accessLocation.uniformResourceIdentifier);
            assertEquals("1.3.6.2.5.4.2.40.1", aiaObj[0].accessMethod);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt", aiaObj[1].accessLocation.uniformResourceIdentifier);
            assertEquals("1.3.6.1.5.5.7.48.2", aiaObj[1].accessMethod);
        };
        CRLTest.prototype.test_AuthorityInfoAccess_toString = function() {
            var der = Hex.toDer("305A302806082B06020504022801861C687474703A2F2F64696769742E72752F736F6D65436572742E637274302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274");
            var aia = new trusted.PKI.AuthorityInfoAccess(der);
            var aiaStr = aia.toString();
            //fail ("This method is not realised");
        };
    }
}
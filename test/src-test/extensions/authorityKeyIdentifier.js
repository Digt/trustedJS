AuthorityKeyIdentifierTest = TestCase("AuthorityKeyIdentifierTest");

//Инициализация параметров
AuthorityKeyIdentifierTest.prototype.setUp = function() {

};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        AuthorityKeyIdentifierTest.prototype.test_AuthorityKeyIdentifier_New_1 = function() {
            assertException(function() {
                new trusted.PKI.AuthorityKeyIdentifier();
            });
        };
        AuthorityKeyIdentifierTest.prototype.test_AuthorityKeyIdentifier_New_2 = function() {
            var der = Hex.toDer("308201AC80142E19D700C30A5A98E70AD0C84B480BE4B1FE658BA1820180A482017C308201783118301606052A85036401120D31303236363035363036363230311A301806082A85030381030101120C3030363636333030333132373137303506035504090C2ED09FD180D0BED181D0BFD0B5D0BAD18220D09AD0BED181D0BCD0BED0BDD0B0D0B2D182D0BED0B220D0B42E203536311E301C06092A864886F70D010901160F636140736B626B6F6E7475722E7275310B30090603550406130252553133303106035504080C2A363620D0A1D0B2D0B5D180D0B4D0BBD0BED0B2D181D0BAD0B0D18F20D0BED0B1D0BBD0B0D181D182D18C3121301F06035504070C18D095D0BAD0B0D182D0B5D180D0B8D0BDD0B1D183D180D0B3312B3029060355040A0C22D097D090D09E2022D09FD0A42022D0A1D09AD09120D09AD0BED0BDD182D183D180223130302E060355040B0C27D0A3D0B4D0BED181D182D0BED0B2D0B5D180D18FD18ED189D0B8D0B920D186D0B5D0BDD182D180312330210603550403131A534B42204B6F6E7475722070726F64756374696F6E204341203382104BFE4677F9E885AD443C620F6B032647");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(der, "2.5.29.35");
            assertNoException(function() {
                new trusted.PKI.AuthorityKeyIdentifier(der);  // По умолчанию 2.5.29.35
            });
            assertObject(aki.CAIssuer);
            assertEquals("4bfe4677f9e885ad443c620f6b032647", aki.CASerialNumber);
            assertEquals("2E19D700C30A5A98E70AD0C84B480BE4B1FE658B", Der.toHex(aki.keyIdentifier));
        };
        // from Object
        AuthorityKeyIdentifierTest.prototype.test_AuthorityKeyIdentifier_New_3 = function() {
            var obj = {authorityCertSerialNumber: "0101"};
            var aki = new trusted.PKI.AuthorityKeyIdentifier(obj);
            assertEquals("0101", aki.CASerialNumber);
            obj = aki.toObject();
            var asn = trusted.ASN.fromObject(obj, "AuthorityKeyIdentifier2");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(asn.encode());
            assertEquals(257, aki.CASerialNumber);
        };
        AuthorityKeyIdentifierTest.prototype.test_AuthorityKeyIdentifier_New_4 = function() {
            var obj = {keyIdentifier: Hex.toDer("010203040506070809")};
            var aki = new trusted.PKI.AuthorityKeyIdentifier(obj);
            assertEquals("010203040506070809", Der.toHex(aki.keyIdentifier));
            obj = aki.toObject();
            var asn = trusted.ASN.fromObject(obj, "AuthorityKeyIdentifier2");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(asn.encode());
            assertEquals("010203040506070809", Der.toHex(aki.keyIdentifier));
        };
        AuthorityKeyIdentifierTest.prototype.test_AuthorityKeyIdentifier_New_5 = function() {
            var str = trusted.ASN.fromObject("My text value", "IA5_STRING").encode();
            var obj = {authorityCertIssuer: [{directoryName: {rdnSequence: [[{type: "2.5.4.3", value: str}]]}}]};
            var aki = new trusted.PKI.AuthorityKeyIdentifier(obj);
            assertEquals("commonName=My text value", aki.CAIssuer.toString());
            obj = aki.toObject();
            var asn = trusted.ASN.fromObject(obj, "AuthorityKeyIdentifier2");
            var aki = new trusted.PKI.AuthorityKeyIdentifier(asn.encode());
            assertEquals("commonName=My text value", aki.CAIssuer.toString());
        };
        AuthorityKeyIdentifierTest.prototype.test_AuthorityKeyIdentifier_New_6 = function() {
            var obj = {};
            var aki = new trusted.PKI.AuthorityKeyIdentifier(obj);
            assertNull(aki.CAIssuer);
            assertNull(aki.CASerialNumber);
            assertNull(aki.keyIdentifier);
        };
    }

    //Свойства
    {

    }
}
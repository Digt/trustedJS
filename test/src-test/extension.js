ExtensionTest = TestCase("ExtensionTest");

//Инициализация параметров
var extn1 = "300E0603551D0F0101FF040403020106"; //KeyUsage
var extn2 = "301D0603551D0E041604146B693D6A18424ADD8F026539FD35248678911630"; //subjectKeyIdentifier

ExtensionTest.prototype.setUp = function() {

};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        ExtensionTest.prototype.test_Extension_New_1 = function() {
            assertException(function() {
                new trusted.PKI.Extension();
            });
        };
        ExtensionTest.prototype.test_Extension_New_2 = function() {
            var obj = new trusted.ASN(Hex.toDer(extn1)).toObject("Extension");
            var extn = new trusted.PKI.Extension(obj);
            assertEquals(true, extn.critical);
            assertEquals("2.5.29.15", extn.OID.value);
            assertEquals("03020106", Der.toHex(extn.value));
        };
        ExtensionTest.prototype.test_Extension_New_2_1 = function() {
            var extn = new trusted.PKI.Extension(Hex.toDer(extn1));
            assertEquals(true, extn.critical);
            assertEquals("2.5.29.15", extn.OID.value);
            assertEquals("03020106", Der.toHex(extn.value));
        };
        ExtensionTest.prototype.test_Extension_New_3 = function() {
            var obj = new trusted.ASN(Hex.toDer(extn2)).toObject("Extension");
            var extn = new trusted.PKI.Extension(obj);
            assertEquals(false, extn.critical);
            assertEquals("2.5.29.14", extn.OID.value);
            assertEquals("04146B693D6A18424ADD8F026539FD35248678911630", Der.toHex(extn.value));
        };
        ExtensionTest.prototype.test_Extension_New_4 = function() {
            assertException(function() {
                new trusted.PKI.Extension("Wrong value");
            });
        };
        ExtensionTest.prototype.test_Extension_New_5 = function() {
            assertException(function() {
                new trusted.PKI.Extension({critical: true, extnID: "2.25.4.16"});
            });
        };
    }

    //Свойства
    {

    }
}
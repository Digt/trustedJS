ExtendedKeyUsageTest = TestCase("ExtendedKeyUsageTest");
//Инициализация параметров
ExtendedKeyUsageTest.prototype.setUp = function() {
};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        ExtendedKeyUsageTest.prototype.test_ExtendedKeyUsage_New_1 = function() {
            assertException(function() {
                new trusted.PKI.ExtendedKeyUsage();
            });
        };

        ExtendedKeyUsageTest.prototype.test_ExtendedKeyUsage_New_2 = function() {
            var extn1 = "304206082B0601050507030206082B0601050507030406072A85030202220606072A85030307080106082A8503030701010106062A850303070106082A8503030700010C";
            var eku = new trusted.PKI.ExtendedKeyUsage(Hex.toDer(extn1));
            assertEquals(true, trusted.isArray(eku.anyExtendedKeyUsage));
            assertEquals(7, eku.anyExtendedKeyUsage.length);
        };

        ExtendedKeyUsageTest.prototype.test_ExtendedKeyUsage_createExtension = function() {
            var eku = new trusted.PKI.ExtendedKeyUsage([
                "2.5.4.1",
                "2.5.4.2",
                "2.5.4.3",
                "2.5.4.4",
                "2.5.4.5"
            ]);

            var der = window.encoder.ExtnKeyUsage(eku).encode();
            
            var eku = new trusted.PKI.ExtendedKeyUsage(der);
            assertEquals(true, trusted.isArray(eku.anyExtendedKeyUsage));
            assertEquals(5, eku.anyExtendedKeyUsage.length);
            assertEquals("2.5.4.1", eku.anyExtendedKeyUsage[0].value);
            assertEquals("2.5.4.2", eku.anyExtendedKeyUsage[1].value);
            assertEquals("2.5.4.3", eku.anyExtendedKeyUsage[2].value);
            assertEquals("2.5.4.4", eku.anyExtendedKeyUsage[3].value);
            assertEquals("2.5.4.5", eku.anyExtendedKeyUsage[4].value);
        };
    }

    //Свойства
    {

    }
}
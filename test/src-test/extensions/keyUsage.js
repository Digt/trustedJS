KeyUsageTest = TestCase("KeyUsageTest");

//Инициализация параметров
KeyUsageTest.prototype.setUp = function() {

};

//Тесты
{
    //Конструктор
    {
        /*
         * Должен быть входной параметр. Иначе ошибка
         */
        KeyUsageTest.prototype.test_KeyUsage_New_1 = function() {
            assertException(function() {
                new trusted.PKI.KeyUsage();
            });
        };
        //Входной параметр строка DER
        KeyUsageTest.prototype.test_KeyUsage_New_2 = function() {
            var val1 = Hex.toDer("03020055");
            var val2 = Hex.toDer("020101"); // не верное значение
            var ku = new trusted.PKI.KeyUsage(val1);
            assertEquals(85, ku.keyUsage);
            assertException(new trusted.PKI.KeyUsage(val2));
        };
        //Входной параметр объект {unusedBit:Number[0-7], encoded: String(Der)}
        KeyUsageTest.prototype.test_KeyUsage_New_2 = function() {
            var val1 = Hex.toDer("03020055");
            var asn = new trusted.ASN(Hex.toDer(val1));
            var obj = asn.toObject("KeyUsage");
            var ku = new trusted.PKI.KeyUsage(obj);
            assertEquals(85, ku.keyUsage);
        };
        //Входной параметр число
        KeyUsageTest.prototype.test_KeyUsage_New_2 = function() {
            var ku = new trusted.PKI.KeyUsage(85);
            assertEquals(85, ku.keyUsage);
        };
    }

    //Методы
    {
        KeyUsageTest.prototype.test_KeyUsage_isDigitalSignature = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020001"));
            assertTrue(ku.isDigitalSignature());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200FE"));
            assertFalse(ku.isDigitalSignature());
        };
        KeyUsageTest.prototype.test_KeyUsage_isNonRepudiation = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020002"));
            assertTrue(ku.isNonRepudiation());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200FD"));
            assertFalse(ku.isNonRepudiation());
        };
        KeyUsageTest.prototype.test_KeyUsage_isKeyEncipherment = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020004"));
            assertTrue(ku.isKeyEncipherment());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200FB"));
            assertFalse(ku.isKeyEncipherment());
        };
        KeyUsageTest.prototype.test_KeyUsage_isDataEncipherment = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020008"));
            assertTrue(ku.isDataEncipherment());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200F7"));
            assertFalse(ku.isDataEncipherment());
        };
        KeyUsageTest.prototype.test_KeyUsage_isKeyAgreement = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020010"));
            assertTrue(ku.isKeyAgreement());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200EF"));
            assertFalse(ku.isKeyAgreement());
        };
        KeyUsageTest.prototype.test_KeyUsage_isKeyCertSign = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020020"));
            assertTrue(ku.isKeyCertSign());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200DF"));
            assertFalse(ku.isKeyCertSign());
        };
        KeyUsageTest.prototype.test_KeyUsage_isCRLSign = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020040"));
            assertTrue(ku.isCRLSign());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030200BF"));
            assertFalse(ku.isCRLSign());
        };
        KeyUsageTest.prototype.test_KeyUsage_isEncipherOnly = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("03020080"));
            assertTrue(ku.isEncipherOnly());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("0302007F"));
            assertFalse(ku.isEncipherOnly());
        };
        KeyUsageTest.prototype.test_KeyUsage_isDecipherOnly = function() {
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("030307807F"));
            assertTrue(ku.isDecipherOnly());
            var ku = new trusted.PKI.KeyUsage(Hex.toDer("0303077FFF"));
            assertFalse(ku.isDecipherOnly());
        };
        
        KeyUsageTest.prototype.test_KeyUsage_toObject = function() {
            
        };
    }
}



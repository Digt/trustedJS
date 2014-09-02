BasicConstraintsTest = TestCase("BasicConstraintsTest");
//Инициализация параметров
BasicConstraintsTest.prototype.setUp = function() {

};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        BasicConstraintsTest.prototype.test_BasicConstraints_New_1 = function() {
            assertException(function() {
                new trusted.PKI.BasicConstraints();
            });
        };
        BasicConstraintsTest.prototype.test_BasicConstraints_New_2 = function() {
            var extn1 = "30060101FF020100";
            var asn = new trusted.ASN(Hex.toDer(extn1));
            var bc = new trusted.PKI.BasicConstraints(asn.toObject("BasicConstraints"));
            assertEquals(true, bc.CA);
            assertEquals(0, bc.pathLength);
        };
        BasicConstraintsTest.prototype.test_BasicConstraints_New_3 = function() {
            var extn1 = "30060101FF020100";
            var der = Hex.toDer(extn1);
            var bc = new trusted.PKI.BasicConstraints(der);
            assertEquals(true, bc.CA);
            assertEquals(0, bc.pathLength);
        };
        BasicConstraintsTest.prototype.test_BasicConstraints_New_4 = function() {
            var extn2 = "3006010100020105";
            var der = Hex.toDer(extn2);
            var bc = new trusted.PKI.BasicConstraints(der);
            assertEquals(false, bc.CA);
            assertEquals(5, bc.pathLength);
        };
        BasicConstraintsTest.prototype.test_BasicConstraints_New_5 = function() {
            var extn3 = "3003010101";
            var der = Hex.toDer(extn3);
            var bc = new trusted.PKI.BasicConstraints(der);
            assertEquals(true, bc.CA);
            assertNull(bc.pathLength);
        };
    }

    //Свойства
    {

    }
}
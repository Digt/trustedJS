SubjectSignToolTest = TestCase("SubjectSignToolTest");
//Инициализация параметров
SubjectSignToolTest.prototype.setUp = function() {
};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        SubjectSignToolTest.prototype.test_SubjectSignTool_New_1 = function() {
            assertException(function() {
                new trusted.PKI.SubjectSignTool();
            });
        };

        // from DER
        SubjectSignToolTest.prototype.test_SubjectSignTool_New_2 = function() {
            var extn1 = "0C2B22D09AD180D0B8D0BFD182D0BED09FD180D0BE20435350222028D0B2D0B5D180D181D0B8D18F20332E3629";
            var sst = new trusted.PKI.SubjectSignTool(Hex.toDer(extn1));
            assertString(sst.subject);
        };

        // from String
        SubjectSignToolTest.prototype.test_SubjectSignTool_New_2 = function() {
            var val = "My test value";
            var sst = new trusted.PKI.SubjectSignTool(val, false);
            assertString(val, sst.subject);
        };

        SubjectSignToolTest.prototype.test_SubjectSignTool_create = function() {
            var obj = "My test value";

            var der = trusted.ASN.fromObject(obj, "SubjectSignTool").encode();
            var sst = new trusted.PKI.SubjectSignTool(der);

            assertEquals(obj, sst.subject);
        };

        SubjectSignToolTest.prototype.test_SubjectSignTool_toString = function() {
            var sst = new trusted.PKI.SubjectSignTool("My test value", false);
            assertEquals("Extension SubjectSignTool(1.2.643.100.112):My test value", sst.toString());
        };

        SubjectSignToolTest.prototype.test_SubjectSignTool_toObject = function() {
            var sst = new trusted.PKI.SubjectSignTool("My test value", false);
            assertEquals("My test value", sst.toObject());
        };
    }
}
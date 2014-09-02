IssuerSignToolTest = TestCase("IssuerSignToolTest");
//Инициализация параметров
IssuerSignToolTest.prototype.setUp = function() {
};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        IssuerSignToolTest.prototype.test_IssuerSignTool_New_1 = function() {
            assertException(function() {
                new trusted.PKI.IssuerSignTool();
            });
        };

        IssuerSignToolTest.prototype.test_IssuerSignTool_New_2 = function() {
            var extn1 = "308201220C2B22D09AD180D0B8D0BFD182D0BED09FD180D0BE20435350222028D0B2D0B5D180D181D0B8D18F20332E36290C5322D0A3D0B4D0BED181D182D0BED0B2D0B5D180D18FD18ED189D0B8D0B920D186D0B5D0BDD182D1802022D09AD180D0B8D0BFD182D0BED09FD180D0BE20D0A3D0A62220D0B2D0B5D180D181D0B8D0B820312E350C4E43D0B5D180D182D0B8D184D0B8D0BAD0B0D18220D181D0BED0BED182D0B2D0B5D182D181D182D0B2D0B8D18F20E2849620D0A1D0A42F3132312D3138353920D0BED1822031372E30362E323031320C4E43D0B5D180D182D0B8D184D0B8D0BAD0B0D18220D181D0BED0BED182D0B2D0B5D182D181D182D0B2D0B8D18F20E2849620D0A1D0A42F3132382D3138323220D0BED1822030312E30362E32303132";
            var ist = new trusted.PKI.IssuerSignTool(Hex.toDer(extn1));
            assertString(ist.CAToolCert);
            assertString(ist.signToolCert);
            assertString(ist.CATool);
            assertString(ist.signTool);
        };

        IssuerSignToolTest.prototype.test_IssuerSignTool_New_3 = function() {
            var ist = new trusted.PKI.IssuerSignTool({
                cAToolCert:"CA tool Certificate",
                signToolCert:"Sign tool Certificate",
                cATool:"CA tool",
                signTool:"sign tool"
            });
            
            assertEquals("CA tool Certificate",ist.CAToolCert);
            assertEquals("Sign tool Certificate",ist.signToolCert);
            assertEquals("CA tool",ist.CATool);
            assertEquals("sign tool",ist.signTool);          
        };
        
        IssuerSignToolTest.prototype.test_IssuerSignTool_create = function() {
            var obj = {
                cAToolCert:"CA tool Certificate",
                signToolCert:"Sign tool Certificate",
                cATool:"CA tool",
                signTool:"sign tool"
            };
            
            var der = trusted.ASN.fromObject(obj,"IssuerSignTool").encode();
            var ist = new trusted.PKI.IssuerSignTool(der);
            
            assertEquals("CA tool Certificate",ist.CAToolCert);
            assertEquals("Sign tool Certificate",ist.signToolCert);
            assertEquals("CA tool",ist.CATool);
            assertEquals("sign tool",ist.signTool);          
        };
        
        IssuerSignToolTest.prototype.test_IssuerSignTool_toString = function() {
            var ist = new trusted.PKI.IssuerSignTool({
                cAToolCert:"CA tool Certificate",
                signToolCert:"Sign tool Certificate",
                cATool:"CA tool",
                signTool:"sign tool"
            });
            assertEquals("Extension SubjectSignTool(1.2.643.100.111):CAToolCert=CA tool Certificate;signToolCert=Sign tool Certificate;CATool=CA tool;signTool=sign tool",ist.toString());
        };
        
        IssuerSignToolTest.prototype.test_IssuerSignTool_toObject = function() {
            var ist = new trusted.PKI.IssuerSignTool({
                cAToolCert:"CA tool Certificate",
                signToolCert:"Sign tool Certificate",
                cATool:"CA tool",
                signTool:"sign tool"
            });
            assertEquals({cAToolCert:"CA tool Certificate",
                signToolCert:"Sign tool Certificate",
                cATool:"CA tool",
                signTool:"sign tool"},ist.toObject());
        };
    }

    //Свойства
    {

    }
}
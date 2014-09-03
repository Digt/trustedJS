PrivateKeyUsagePeriodTest = TestCase("PrivateKeyUsagePeriod");

PrivateKeyUsagePeriodTest.prototype.setUp = function() {

};

//Test
{
    //Constructor
    {
        //Test input parametrs
        PrivateKeyUsagePeriodTest.prototype.test_new_1 = function() {
            assertException(function() {
                new trusted.PKI.PrivateKeyUsagePeriod();
            });
        };
        
        //Test Der        
        PrivateKeyUsagePeriodTest.prototype.test_new_2 = function() {
            var der = Hex.toDer("3022800F32303132303830393131343330305A810F32303133303830393131343330305A");
            var ext = new trusted.PKI.PrivateKeyUsagePeriod(der);
            assertEquals(2013,ext.notAfter.getFullYear());
            assertEquals(8,ext.notAfter.getMonth());
            assertEquals(9,ext.notAfter.getDate());
            assertEquals(11,ext.notAfter.getHours());
            assertEquals(43,ext.notAfter.getMinutes());
            assertEquals(0,ext.notAfter.getSeconds());
            assertEquals(2012,ext.notBefore.getFullYear());
            assertEquals(8,ext.notBefore.getMonth());
            assertEquals(9,ext.notBefore.getDate());
            assertEquals(11,ext.notBefore.getHours());
            assertEquals(43,ext.notBefore.getMinutes());
            assertEquals(0,ext.notBefore.getSeconds());
        };
        
        //Test before/after        
        PrivateKeyUsagePeriodTest.prototype.test_new_3 = function() {
            var date1 = new Date();
            var obj = {
                notBefore: date1,
                notAfter: new Date()
            };
            var ext = new trusted.PKI.PrivateKeyUsagePeriod(obj);
            assertEquals(date1,ext.notAfter);
        };

        
        //Test empty object        
        PrivateKeyUsagePeriodTest.prototype.test_new_4 = function() {
            var obj = {};            
            var ext = new trusted.PKI.PrivateKeyUsagePeriod(obj);
            assertNull(ext.notAfter);
            assertNull(ext.notBefore);
        };    
        
        
        //Test to object        
        PrivateKeyUsagePeriodTest.prototype.test_toObject = function() {
            var der = Hex.toDer("3022800F32303132303830393131343330305A810F32303133303830393131343330305A");
            var extn = new trusted.PKI.PrivateKeyUsagePeriod(der);
            var obj = extn.toObject();
            assertNotUndefined(obj.notAfter);
            assertNotUndefined(obj.notBefore);
        
        };
        
       
    }
}
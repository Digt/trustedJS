DistributionPointNameTest = TestCase("DistributionPointName");

DistributionPointNameTest.prototype.setUp = function() {
    
};

{
    {
        DistributionPointNameTest.prototype.test_new_1 = function() {
            assertException(function() {
                new trusted.PKI.DistributionPointName();
            });
        };
        
        DistributionPointNameTest.prototype.test_new_2 = function() {
            var der = Hex.toDer("A0248622687474703A2F2F7265657374722D706B692E72752F6364702F76677563312E63726C");
            var des = new trusted.PKI.DistributionPointName(der);
            assertEquals("http://reestr-pki.ru/cdp/vguc1.crl",des.fullName);
            
        };
       
        DistributionPointNameTest.prototype.test_fromObject = function() {
            //var der = Hex.toDer("A0248622687474703A2F2F7265657374722D706B692E72752F6364702F76677563312E63726C");
            var obj = {
                fullName: [{dNSName:"My value"}]
            };
            var des = new trusted.PKI.DistributionPointName(obj);
            console.log(des);
            assertEquals("My value",des.fullName);
        };
       
        DistributionPointNameTest.prototype.test_toObject = function(){
            var der = Hex.toDer("8622687474703A2F2F7265657374722D706B692E72752F6364702F76677563312E63726C");
            var gn = new trusted.PKI.GeneralName(der);
            var obj = {
               fullName: [
                   gn.toObject(),
                   gn.toObject()
               ]
            };
            var des = new trusted.PKI.DistributionPointName(obj);
            var o = des.toObject();
            assertEquals(o,obj);
        };
        //Empty object
        DistributionPointNameTest.prototype.test_toObject2 = function(){
           var obj = {};
           assertException(function() {
                new trusted.PKI.DistributionPointName(obj);
            });
        };
        
        DistributionPointNameTest.prototype.test_toString = function(){
            fail("Test is not realised");
        };
    }
}
AuthorityInfoAccessTest = TestCase("AuthorityInfoAccess");

AuthorityInfoAccessTest.prototype.setUp = function() {
    
};

{
    {
        AuthorityInfoAccessTest.prototype.test_new_1 = function() {
            assertException(function() {
                new trusted.PKI.AuthorityInfoAccess();
            });
        };
        
        AuthorityInfoAccessTest.prototype.test_new_2 = function(){
            var der = Hex.toDer("3060302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274302E06082B060105050730028622687474703A2F2F7265657374722D706B692E72752F6364702F76677563312E637274");
            var des = new trusted.PKI.AuthorityInfoAccess(der);
            assertEquals(2,des.descriptions.length);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt",des.descriptions[0].location);
            assertEquals("1.3.6.1.5.5.7.48.2",des.descriptions[0].method.value); 
        };

        AuthorityInfoAccessTest.prototype.test_fromObject = function(){
            var der = Hex.toDer("302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274");
            var des = new trusted.PKI.AccessDescription(der);
            var obj=[
                des.toObject(),
                des.toObject(),
                des.toObject()
            ];
            var des = new trusted.PKI.AuthorityInfoAccess(obj);
            assertEquals(3,des.descriptions.length);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt",des.descriptions[0].location);
            assertEquals("1.3.6.1.5.5.7.48.2",des.descriptions[0].method.value); 
            
        };
        
        AuthorityInfoAccessTest.prototype.test_toObject = function(){
            var der = Hex.toDer("3060302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274302E06082B060105050730028622687474703A2F2F7265657374722D706B692E72752F6364702F76677563312E637274");
            var des = new trusted.PKI.AuthorityInfoAccess(der);
            var obj = des.toObject();
            assertArray(obj);
            assertNotUndefined(obj[0].accessLocation);
            assertNotUndefined(obj[0].accessMethod);
            
        };
        
        
        AuthorityInfoAccessTest.prototype.test_subjectInfoAccess = function(){
            var der = Hex.toDer("3060302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274302E06082B060105050730028622687474703A2F2F7265657374722D706B692E72752F6364702F76677563312E637274");
            var des = new trusted.PKI.SubjectInfoAccess(der);
            assertEquals(2,des.descriptions.length);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt",des.descriptions[0].location);
            assertEquals("1.3.6.1.5.5.7.48.2",des.descriptions[0].method.value); 
        };
    }

}
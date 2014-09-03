AccessDescriptionTest = TestCase("AccessDescription");

AccessDescriptionTest.prototype.setUp = function() {
    
};

{
    {                
        AccessDescriptionTest.prototype.test_new_1 = function() {
            assertException(function() {
                new trusted.PKI.AccessDescription();
            });
        };
        
        AccessDescriptionTest.prototype.test_new_2 = function(){
            var der = Hex.toDer("302E06082B060105050730028622687474703A2F2F726F7374656C65636F6D2E72752F6364702F76677563312E637274");
            var des = new trusted.PKI.AccessDescription(der);
            assertEquals("http://rostelecom.ru/cdp/vguc1.crt",des.location);
            assertEquals("1.3.6.1.5.5.7.48.2",des.method.value);            
        };        
       
       AccessDescriptionTest.prototype.test_new_fromObject = function(){
           var der = Hex.toDer("A41C301A3118301606082A850303810D0101120A31323135303139383832");
           var gn = new trusted.PKI.GeneralName(der);
           var obj = {
               accessMethod: "2.5.29.23" ,
               accessLocation: gn.toObject()
           };
           var des = new trusted.PKI.AccessDescription(obj);
            assertEquals("1.2.643.3.141.1.1=1215019882",des.location.name.toString());
            assertEquals("2.5.29.23",des.method.value);           
       };
       //Test create object whith parametrs
       AccessDescriptionTest.prototype.test_toObject = function(){
           var der = Hex.toDer("A41C301A3118301606082A850303810D0101120A31323135303139383832");
           var gn = new trusted.PKI.GeneralName(der);
           var obj = {
               accessMethod: "2.5.29.23" ,
               accessLocation: gn.toObject()
           };
           var des = new trusted.PKI.AccessDescription(obj);
           var o =des.toObject();
           assertEquals(o,obj);
       };
        //Test create from object whith uncorrect parametrs
        AccessDescriptionTest.prototype.test_new_fromObject2 = function(){
           var obj = {
                accessMethod: "2.5.29.23"
           };
            assertException(function() {
                new trusted.PKI.AccessDescription(obj);
            });
       
        };
        //Test create from object whith uncorrect parametrs 2
       AccessDescriptionTest.prototype.test_toObject2 = function(){
           var der = Hex.toDer("A41C301A3118301606082A850303810D0101120A31323135303139383832");
           var gn = new trusted.PKI.GeneralName(der);
           var obj = {
               accessLocation: gn.toObject()
           };
           var des = new trusted.PKI.AccessDescription(obj);
           var o =des.toObject();
           assertEquals(o,obj);
       };
       
       
       AccessDescriptionTest.prototype.test_toString = function(){
           fail("Test is not realised");
       };
       
    }
}

        

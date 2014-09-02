OIDTest = TestCase("OIDTest");

//Инициализация параметров
OIDTest.prototype.setUp = function() {
    
};

//Тесты
{
    //Конструктор
    {
        OIDTest.prototype.test_OID_New_1 = function() {
            var oid = new trusted.PKI.OID();
            //assertTrue(oid instanceof trusted.PKI.OID);
            assertNull(oid.name);
            assertNull(oid.comment);
            assertUndefined(oid.value);
        };
        
        OIDTest.prototype.test_OID_New_2 = function() {
            var oid = new trusted.PKI.OID("1.2.3");
            //assertBoolean(oid instanceof trusted.PKI.OID);
            assertEquals('1.2.3',oid.name);
            assertEquals('', oid.comment);
            assertEquals("1.2.3", oid.value);
        };
    }

    // Свойста
    {
        OIDTest.prototype.test_OID_value_1 = function() {
            var oid = new trusted.PKI.OID();
            oid.value = "2.5.4.3"; // known name
            assertEquals("commonName",oid.name);
            assertEquals("X.520 DN component",oid.comment);
            assertEquals("2.5.4.3",oid.value);
            
            oid.value = "2.5.4.3.0.0.1.1"; // unknown name
            assertEquals("2.5.4.3.0.0.1.1",oid.name);
            assertEquals("",oid.comment);
            assertEquals("2.5.4.3.0.0.1.1",oid.value);
            
            trusted.oids["2.5.4.3.0.0.1"]={
                d: "myOIDname",
                c: "myOIDcomment"
            };
            oid.value = "2.5.4.3.0.0.1"; // known name
            assertEquals("myOIDname",oid.name);
            assertEquals("myOIDcomment",oid.comment);
            assertEquals("2.5.4.3.0.0.1",oid.value);
           
        };
    }
}
QualifierInfoTest = TestCase("QualifierInfo");
QualifierInfoTest.prototype.setUp = function(){
    
};

{
    {
        QualifierInfoTest.prototype.test_New_1 = function() {
            assertException(function() {
                new trusted.PKI.QualifierInfo();
            });
        };
        //TEST2 OID value
        QualifierInfoTest.prototype.test_New_2 = function() {
            var der = Hex.toDer("302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379");
            var tmp = new trusted.PKI.QualifierInfo(der);
            assertEquals("1.3.6.1.5.5.7.2.1",tmp.OID.value);
            assertEquals("http://ca.skbkontur.ru/policy",tmp.CPSPointer);
            
        };
        //TEST3 from Object
        QualifierInfoTest.prototype.test_fromObject = function(){
        var obj = {
            qualifier:Hex.toDer("020101"),
            policyQualifierId:"1.3.6.1.5.5.7.2.1"
        };
            var tmp = new trusted.PKI.QualifierInfo(obj);
            assertEquals("1.3.6.1.5.5.7.2.1",tmp.OID.value);
            assertEquals("020101",Der.toHex(tmp.encoded));
        };
        //TEST4 to string
        QualifierInfoTest.prototype.test_toString = function(){
            var der = Hex.toDer("302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379");
            var tmp = new trusted.PKI.QualifierInfo(der);
            var str = tmp.toString();
            //assertEquals("Maybe QualifierInfo doesn't have toString method","",str);
            
        };
        
        //TEST5 to Object
        QualifierInfoTest.prototype.test_fromObject = function(){
            //var der = Hex.toDer("302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379");
            //var tmp = new trusted.PKI.QualifierInfo(der);
            var obj = {
                qualifier:Hex.toDer("020101"),
                policyQualifierId:"1.3.4"
            };
            var crobj = new trusted.PKI.QualifierInfo(obj);
            console.log(crobj);
            assertEquals("020101",Der.toHex(crobj.encoded));
            assertEquals("1.3.4",crobj.OID.value);
        };
        //TEST6 Policy Information
        QualifierInfoTest.prototype.test_PolicyInformation_new_1 = function(){
            assertException(function() {
                new trusted.PKI.PolicyInformation();
            });
        };
        //TEST7 Policy Information
        QualifierInfoTest.prototype.test_PolicyInformation_new_2 = function(){
            var der = Hex.toDer("308006072A8503030702013080302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C696379302906082B06010505070201161D687474703A2F2F63612E736B626B6F6E7475722E72752F706F6C69637900000000");
            var dps = new trusted.PKI.PolicyInformation(der);
            var oidValue = dps.qualifiers[0].CPSPointer;
            assertEquals("http://ca.skbkontur.ru/policy",oidValue);
        };
        //TEST8 Policy Information
        QualifierInfoTest.prototype.test_PolicyInformation_toObject = function(){
            var obj = {
                policyIdentifier:"0",
        policyQualifiers: [
                    {
                        policyQualifierId: "1.3",
                        qualifier: Hex.toDer("020101")
                    },
                    {
                        policyQualifierId: "1.3",
                        qualifier: Hex.toDer("020102")
                    }
                ]
            };
            var tmp = new trusted.PKI.PolicyInformation(obj);
            //console.log(tmp);
            
        };
    }
}
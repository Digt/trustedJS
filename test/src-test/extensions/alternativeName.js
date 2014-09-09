AlternativeNameTest = TestCase("AlternativeNameTest");

//Инициализация параметров
AlternativeNameTest.prototype.setUp = function() {

};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        AlternativeNameTest.prototype.test_AlternativeName_New_1 = function() {
            assertException(function() {
                new trusted.PKI.IssuerAlternativeName();
            });
        };
        // issuer
        AlternativeNameTest.prototype.test_AlternativeName_New_2 = function() {
            var der = Hex.toDer("305A810456616C3187030201018803550406A4423040311E300806035504010201013008060355040202010230080603550403020103311E300806035504040201043008060355040502010530080603550406020106820456616C33");
            var ian = new trusted.PKI.IssuerAlternativeName(der);
            assertEquals(5, ian.generalNames.length);
            assertEquals("Val1;020101;countryName (2.5.4.6);aliasedEntryName=1+knowledgeInformation=2+commonName=3;surname=4+serialNumber=5+countryName=6;Val3", ian.toString());
        };
        // subject
        AlternativeNameTest.prototype.test_AlternativeName_New_3 = function() {
            var der = Hex.toDer("305A810456616C3187030201018803550406A4423040311E300806035504010201013008060355040202010230080603550403020103311E300806035504040201043008060355040502010530080603550406020106820456616C33");
            var ian = new trusted.PKI.SubjectAlternativeName(der);
            assertEquals(5, ian.generalNames.length);
            assertEquals("Val1;020101;countryName (2.5.4.6);aliasedEntryName=1+knowledgeInformation=2+commonName=3;surname=4+serialNumber=5+countryName=6;Val3", ian.toString());
        };
    }

    //Свойства
    {

    }
}
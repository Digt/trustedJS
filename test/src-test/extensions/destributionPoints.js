DistributionPointsTest = TestCase("DistributionPoints");

//Инициализация параметров
DistributionPointsTest.prototype.setUp = function() {

};

//Тесты
{
    //Конструктор
    {
        /*
         * 
         */
        DistributionPointsTest.prototype.test_DistributionPoints_New_1 = function() {
            assertException(function() {
                new trusted.PKI.CRLDistributionPoints();
            });
        };
        // issuer
        DistributionPointsTest.prototype.test_DistributionPoints_New_2 = function() {
            var der = Hex.toDer("306F3035A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C3036A034A0328630687474703A2F2F636470322E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C");
            var dps = new trusted.PKI.CRLDistributionPoints(der);
            assertEquals(2, dps.distributionPoints.length);
        };
        DistributionPointsTest.prototype.test_DistributionPoints_New_2 = function() {
            var der = Hex.toDer("306F3035A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C3036A034A0328630687474703A2F2F636470322E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C");
            var dps = new trusted.PKI.CRLDistributionPoints(der);
            var obj = dps.toObject();
            assertArray(obj);
            assertEquals(2, obj.length);
            assertTrue("distributionPoint" in obj[0]);
        };
        DistributionPointsTest.prototype.test_FreshestCRL_New_2 = function() {
            var der = Hex.toDer("306F3035A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C3036A034A0328630687474703A2F2F636470322E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C");
            var dps = new trusted.PKI.FreshestCRL(der);
            var obj = dps.toObject();
            assertArray(obj);
            assertEquals(2, obj.length);
            assertTrue("distributionPoint" in obj[0]);
        };


        // Distribution point
        DistributionPointsTest.prototype.test_DistributionPoint_New_1 = function() {
            assertException(function() {
                new trusted.PKI.IssuerDistributionPoint();
            });
        };
        DistributionPointsTest.prototype.test_DistributionPoint_New_2 = function() {
            var der = Hex.toDer("3035A033A031862F687474703A2F2F6364702E736B626B6F6E7475722E72752F6364702F6B6F6E7475722D6361332D323031332E63726C");
            var dp = new trusted.PKI.DistributionPoint(der);
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", dp.getURL());
        };
        //from object
        DistributionPointsTest.prototype.test_DistributionPoint_New_3 = function() {
            var dp = new trusted.PKI.CRLDistributionPoints([{
                    cRLIssuer: [{uniformResourceIdentifier: "http://cdp.skbkontur.ru"}],
                    distributionPoint: {fullName: [{uniformResourceIdentifier: "http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl"}]},
                    reasons: new BitString(trusted.PKI.ReasonFlags.KeyCompromise)
                }]);
            assertEquals("http://cdp.skbkontur.ru", dp.CRLIssuer.toString());
            assertEquals("http://cdp.skbkontur.ru/cdp/kontur-ca3-2013.crl", dp.distributionPoint.fullName.toString());
            assertEquals(260, dp.reasons);
        };
    }

    //Свойства
    {

    }
}
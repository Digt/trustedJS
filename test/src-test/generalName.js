GeneralNameTest = TestCase("GeneralNameTest");

GeneralNameTest.prototype.setUp = function() {

};

//Тесты
{
    //RDNAttribute
    GeneralNameTest.prototype.test_RDNAttribute_New_1 = function() {
        assertException(function() {
            new trusted.PKI.RDNAttribute();
        });
    };
    // из DER
    GeneralNameTest.prototype.test_RDNAttribute_New_2 = function() {
        var der = Hex.toDer("3009060355040613025255");
        var att = new trusted.PKI.RDNAttribute(der);
        assertNotUndefined(att);
        assertEquals(att.type.value, "2.5.4.6");
        assertString(att.value); // DER значение
        assertEquals(att.text, "RU");

    };

    // из Object
    GeneralNameTest.prototype.test_RDNAttribute_New_2 = function() {
        var obj = {
            type: new trusted.PKI.OID("2.5.4.6"),
            value: Hex.toDer("020101")
        };
        var att = new trusted.PKI.RDNAttribute(obj);
        assertNotUndefined(att);
        assertEquals(att.type.value, "2.5.4.6");
        assertString(att.value); // DER значение
        assertEquals(att.text, "1");
    };

    // encode
    GeneralNameTest.prototype.test_RDNAttribute_encode = function() {
        var obj = {
            type: "2.5.4.6",
            value: Hex.toDer("020101")
        };

        var att = new trusted.PKI.RDNAttribute(obj);

        var der = encoder.RDNAttribute(att).encode();
        assertEquals("30080603550406020101", Der.toHex(der));
    };

    GeneralNameTest.prototype.test_RDNAttribute_toString = function() {
        var obj = {
            type: "2.5.4.6",
            value: Hex.toDer("020101")
        };

        var att = new trusted.PKI.RDNAttribute(obj);
        assertEquals("countryName=1", att.toString());
    };

    GeneralNameTest.prototype.test_RDNAttribute_format = function() {
        var obj = {
            type: "2.5.4.6",
            value: Hex.toDer("020101")
        };

        var att = new trusted.PKI.RDNAttribute(obj);
        assertEquals("newName=1", att.format({"2.5.4.6": "newName"}));
    };

    GeneralNameTest.prototype.test_RDNAttribute_format_array = function() {
        var obj = {
            type: "2.5.4.6",
            value: Hex.toDer("30800201010201020201030201040201050000")
        };

        var att = new trusted.PKI.RDNAttribute(obj);
        assertEquals("countryName=1+2+3+4+5", att.format("+"));
        assertEquals("2.5.4.6=1/2/3/4/5", att.format("/", {}));
    };

    // RDN
    GeneralNameTest.prototype.test_RDN_New_1 = function() {
        assertException(function() {
            new trusted.PKI.RDN();
        });
    };
    // из DER
    GeneralNameTest.prototype.test_RDN_New_2 = function() {
        var der = Hex.toDer("308030090603550406130252550000");
        var rdn = new trusted.PKI.RDN(der);
        assertNotUndefined(rdn);
        assertEquals(1, rdn.attributes.length);
        var att = rdn.attributes[0];
        assertEquals(att.type.value, "2.5.4.6");
        assertString(att.value); // DER значение
        assertEquals(att.text, "RU");
    };
    GeneralNameTest.prototype.test_RDN_New_3 = function() {
        var der = Hex.toDer("3080300906035504061302525530090603550406130252550000");
        var rdn = new trusted.PKI.RDN(der);
        assertNotUndefined(rdn);
        assertEquals(2, rdn.attributes.length);
        var att = rdn.attributes[0];
        assertEquals(att.type.value, "2.5.4.6");
        assertString(att.value); // DER значение
        assertEquals(att.text, "RU");
    };
    // from Object
    GeneralNameTest.prototype.test_RDN_New_4 = function() {
        var obj = [
            {type: "2.5.4.1", value: "123"},
            {type: "2.5.4.2", value: "456"},
            {type: "2.5.4.3", value: "789"}
        ];
        var rdn = new trusted.PKI.RDN(obj);
        assertNotUndefined(rdn);
        assertEquals(3, rdn.attributes.length);
        var att = rdn.attributes[0];
        assertEquals(att.type.value, "2.5.4.1");
        assertEquals("123", att.value);
        var att = rdn.attributes[1];
        assertEquals(att.type.value, "2.5.4.2");
        assertEquals("456", att.value);
        var att = rdn.attributes[2];
        assertEquals(att.type.value, "2.5.4.3");
        assertEquals("789", att.value);
    };

    GeneralNameTest.prototype.test_RDN_encode = function() {
        var obj = [
            {type: "2.5.4.1", value: Hex.toDer("020101")},
            {type: "2.5.4.2", value: Hex.toDer("020102")},
            {type: "2.5.4.3", value: Hex.toDer("020103")}
        ];
        var rdn = new trusted.PKI.RDN(obj);

        var der = encoder.RDN(rdn).encode();
        assertEquals("311E300806035504010201013008060355040202010230080603550403020103", Der.toHex(der));
    };
    GeneralNameTest.prototype.test_RDN_format = function() {
        var obj = [
            {type: "2.5.4.1", value: Hex.toDer("020101")},
            {type: "2.5.4.2", value: Hex.toDer("020102")},
            {type: "2.5.4.3", value: Hex.toDer("30800201030201040201050000")},
            {type: "2.5.4.2", value: Hex.toDer("020106")}
        ];
        var rdn = new trusted.PKI.RDN(obj);

        var str = rdn.toString();
        assertEquals("aliasedEntryName=1;knowledgeInformation=2;commonName=3+4+5;knowledgeInformation=6", str);
        var str = rdn.format('^');
        assertEquals("aliasedEntryName=1^knowledgeInformation=2^commonName=3+4+5^knowledgeInformation=6", str);
        var str = rdn.format({"2.5.4.2": "newName2"});
        assertEquals("2.5.4.1=1;newName2=2;2.5.4.3=3+4+5;newName2=6", str);
        var str = rdn.format("^", {"2.5.4.2": "newName2"});
        assertEquals("2.5.4.1=1^newName2=2^2.5.4.3=3+4+5^newName2=6", str);
    };

    // Name
    GeneralNameTest.prototype.test_Name_New_1 = function() {
        assertException(function() {
            new trusted.PKI.Name();
        });
    };
    // из DER
    GeneralNameTest.prototype.test_Name_New_2 = function() {
        var der = Hex.toDer("3050310B3009060355040613025553310D300B060355040A13044D53465431323030060355040313294D6963726F736F66742041757468656E7469636F646528746D2920526F6F7420417574686F72697479");
        var n = new trusted.PKI.Name(der);
        assertEquals(
                "commonName=Microsoft Authenticode(tm) Root Authority",
                n.RDNs[2].toString()
                );
    };

    // from Object
    GeneralNameTest.prototype.test_Name_New_4 = function() {
        var RDN1 = [
            {type: "2.5.4.1", value: Hex.toDer("020101")},
            {type: "2.5.4.2", value: Hex.toDer("020102")},
            {type: "2.5.4.3", value: Hex.toDer("020103")}
        ];
        var RDN2 = [
            {type: "2.5.4.4", value: Hex.toDer("020104")},
            {type: "2.5.4.5", value: Hex.toDer("020105")},
            {type: "2.5.4.6", value: Hex.toDer("020106")}
        ];
        var obj = {rdnSequence: [RDN1, RDN2]};
        var n = new trusted.PKI.Name(obj);

        assertEquals("aliasedEntryName=1;knowledgeInformation=2;commonName=3", n.RDNs[0].toString());
        assertEquals("surname=4;serialNumber=5;countryName=6", n.RDNs[1].toString());
    };

    GeneralNameTest.prototype.test_Name_encode = function() {
        var RDN1 = [
            {type: "2.5.4.1", value: Hex.toDer("020101")},
            {type: "2.5.4.2", value: Hex.toDer("020102")},
            {type: "2.5.4.3", value: Hex.toDer("30800201030201070000")}
        ];
        var RDN2 = [
            {type: "2.5.4.4", value: Hex.toDer("020104")},
            {type: "2.5.4.5", value: Hex.toDer("020105")},
            {type: "2.5.4.6", value: Hex.toDer("020106")}
        ];
        var obj = {rdnSequence: [RDN1, RDN2]};
        var n = new trusted.PKI.Name(obj);

        var der = encoder.Name(n).encode();
        assertEquals("304731253008060355040102010130080603550402020102300F060355040330800201030201070000311E300806035504040201043008060355040502010530080603550406020106", Der.toHex(der));
    };

    GeneralNameTest.prototype.test_Name_getAttributes = function() {
        var RDN1 = [
            {type: "2.5.4.1", value: Hex.toDer("020101")},
            {type: "2.5.4.2", value: Hex.toDer("020102")},
            {type: "2.5.4.3", value: Hex.toDer("30800201030201070000")}
        ];
        var RDN2 = [
            {type: "2.5.4.4", value: Hex.toDer("020104")},
            {type: "2.5.4.1", value: Hex.toDer("020105")},
            {type: "2.5.4.6", value: Hex.toDer("020106")},
            {type: "2.5.4.1", value: Hex.toDer("020107")}
        ];
        var obj = {rdnSequence: [RDN1, RDN2]};
        var n = new trusted.PKI.Name(obj);

        assertEquals(3, n.getAttributes("2.5.4.1").length);
        assertEquals(1, n.getAttributes("2.5.4.4").length);
        assertEquals(0, n.getAttributes("2.5.4.10").length);
    };

    // GenerealName
    GeneralNameTest.prototype.test_GeneralName_New_1 = function() {
        assertException(function() {
            new trusted.PKI.GeneralName();
        });
    };
    // из DER
    GeneralNameTest.prototype.test_GeneralName_New_2 = function() {
        var der = Hex.toDer("A41C301A3118301606082A850303810D0101120A31323135303139383832");
        var n = new trusted.PKI.GeneralName(der);
        assertEquals("1.2.643.3.141.1.1=1215019882", n.name.toString());
        assertEquals(4, n.type);
    };

    // from Object
    GeneralNameTest.prototype.test_GeneralName_New_3 = function() {
        var obj = {otherName: {typeId: "2.5.4.6", value: Hex.toDer("304206082B0601050507030206082B0601050507030406072A85030202220606072A85030307080106082A8503030701010106062A850303070106082A8503030700010C")}};
        var n = new trusted.PKI.GeneralName(obj);
        assertObject(n.name);
        assertEquals(0, n.type);
        assertTrue(n.isOtherName());
    };

    GeneralNameTest.prototype.test_GeneralName_New_4 = function() {
        var obj = {rfc822Name: "My name"};
        var n = new trusted.PKI.GeneralName(obj);
        assertEquals("My name", n.name);
        assertEquals(1, n.type);
        assertTrue(n.isRFC822Name());
    };

    GeneralNameTest.prototype.test_GeneralName_New_5 = function() {
        var obj = {directoryName: {rdnSequence: [[{type: "2.5.4.6", value: "My value"}]]}};
        var n = new trusted.PKI.GeneralName(obj);
        assertObject(n.name);
        assertEquals(4, n.type);
        assertTrue(n.isDirectoryName());
    };
    GeneralNameTest.prototype.test_GeneralName_New_6 = function() {
        var obj = {uniformResourceIdentifier: "My value"};
        var n = new trusted.PKI.GeneralName(obj);
        assertEquals("My value", n.name);
        assertEquals(6, n.type);
        assertTrue(n.isUniformResourceIdentifier());
    };
    GeneralNameTest.prototype.test_GeneralName_New_7 = function() {
        var obj = {iPAddress: Hex.toDer("020109")};
        var n = new trusted.PKI.GeneralName(obj);
        assertEquals("020109", Der.toHex(n.name));
        assertEquals(7, n.type);
        assertTrue(n.isIPAddress());
    };
    GeneralNameTest.prototype.test_GeneralName_New_8 = function() {
        var obj = {registeredID: "2.5.4.6"};
        var n = new trusted.PKI.GeneralName(obj);
        assertEquals("countryName (2.5.4.6)", n.name.toString());
        assertEquals(8, n.type);
        assertTrue(n.isRegisteredID());
    };
    GeneralNameTest.prototype.test_GeneralName_New_9 = function() {
        var obj = {unknownName: "2.5.4.6"};
        assertException(function() {
            new trusted.PKI.GeneralName(obj);
        });
    };

    // GenerealNames
    GeneralNameTest.prototype.test_GeneralNames_New_1 = function() {
        assertException(function() {
            new trusted.PKI.GeneralNames();
        });
    };
    // из DER
    GeneralNameTest.prototype.test_GeneralNames_New_2 = function() {
        var der = Hex.toDer("3016810456616C3187030201018803550406820456616C33");
        var n = new trusted.PKI.GeneralNames(der);
        assertEquals(4, n.generalNames.length);
        assertEquals("Val1;020101;countryName (2.5.4.6);Val3", n.toString());
    };

    // from Object
    GeneralNameTest.prototype.test_GeneralNames_New_3 = function() {
        var obj = [
            {rfc822Name: "Val1"},
            {iPAddress: Hex.toDer("020101")},
            {registeredID: "2.5.4.6"},
            {dNSName: "Val3"}];
        var n = new trusted.PKI.GeneralNames(obj);
        assertEquals("Val1;020101;countryName (2.5.4.6);Val3", n.toString());
    };

    // to String
    GeneralNameTest.prototype.test_GeneralNames_New_2 = function() {
        var der = Hex.toDer("3016810456616C3187030201018803550406820456616C33");
        var n = new trusted.PKI.GeneralNames(der);
        var str = n.toString();
        assertEquals("Val1;020101;countryName (2.5.4.6);Val3", str);
    };
}



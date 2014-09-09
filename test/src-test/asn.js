ASNTest = TestCase("ASN");

//Инициализация параметров
ASNTest.prototype.setUp = function() {

};

function DER(a) {
    var s = '';
    for (var i = 0; i < a.length; i++)
        s += String.fromCharCode(a[i]);
    return s;
}

function DerToHex(der) {
    var hex = '';
    for (var i = 0; i < der.length; i++) {
        var char = der.charCodeAt(i).toString(16);
        if ((char.length % 2) > 0)
            char = "0" + char;
        hex += char;
    }
    return hex;
}

trusted.schemas.Test1 = {
    type: "SEQUENCE",
    value: {
        number: {type: "Number"}
    }
};

trusted.schemas.Number = {type: "INTEGER"};
trusted.schemas.Boolean = {type: "BOOLEAN"};

//Тесты
{
    //Конструктор
    {
        /*
         * Объект ASN можно создать без параметров
         */
        ASNTest.prototype.test_ASN_new_1 = function() {
            var asn = new trusted.ASN();
            assertTrue(asn instanceof trusted.ASN);
        };
        /*
         * Объект ASN можно создать c параметром. Параметр - строка содержащая DER код ASN объекта.
         * Вызывается функция ASN.import
         * Иначе возникает ошибка.
         */
        ASNTest.prototype.test_ASN_new_2 = function() {
            assertException(
                    function() {
                        new trusted.ASN(1);
                    },
                    undefined);
        };
    }

    //Методы
    {
        // <editor-fold defaultstate="collapsed" desc=" import ">
        /**
         * Входной параметр должен быть строкой, иначе ошибка.
         */
        ASNTest.prototype.test_ASN_import_1 = function() {
            assertException(
                    function() {
                        new trusted.ASN(1);
                    },
                    undefined);
        };

        /**
         * параметр должен быть строкой DER соответствующей структуре ASN иначе ошибка.
         * Верная ASN структура
         */
        ASNTest.prototype.test_ASN_import_2 = function() {
            var asn = new trusted.ASN();
            var der = DER([48, 3, 2, 1, 2]);
            asn.import(der);
        };

        /**
         * параметр должен быть строкой DER соответствующей структуре ASN иначе ошибка.
         * ASN структура содержит ошибку
         */
        ASNTest.prototype.test_ASN_import_3 = function() {
            var asn = new trusted.ASN();
            var der = DER([48, 4, 2, 1, 2]);
            assertException(
                    function() {
                        asn.import(der);
                    },
                    undefined);
        };

        // </editor-fold>

        // <editor-fold defaultstate="collapsed" desc=" toObject ">

        /*
         * Конвертирует asn структуру в Объект по указанной схеме.
         */

        /*
         * Если ASN структура не инициализирована (не вызван метод input) вызывается ошибка.
         */
        ASNTest.prototype.test_ASN_toObject = function() {
            var asn = new trusted.ASN();
            assertException(
                    function() {
                        asn.toObject("Test1");
                    },
                    undefined);
        };

        /*
         * Схема может быть передана в виде строки или объекта. Иначе ошибка.
         */
        ASNTest.prototype.test_ASN_toObject_1 = function() {
            var asn = new trusted.ASN(DER([48, 3, 2, 1, 2]));
            assertException(
                    function() {
                        asn.toObject(1);
                    },
                    undefined);
        };

        /*
         * Схема может быть передана в виде строки или объекта.
         */
        ASNTest.prototype.test_ASN_toObject_2 = function() {
            var asn = new trusted.ASN(DER([48, 3, 2, 1, 2]));
            var obj = asn.toObject("Test1");
            assertEquals(2, obj.number);
        };

        // OPTIONAL
        /*
         * optional: <значение>;
         * [0-MAX] - индекс опционального поля, специальный ASN тэг с указателем индекса.
         * -1 - поле является поциональным, но не имеет специального тэга.
         */
        ASNTest.prototype.test_ASN_toObject_OPTIONAL = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val0: {type: "INTEGER", explicit: true, context: 0, optional: true, index: 0},
                    val1: {type: "INTEGER", explicit: true, context: 1, optional: true, index: 0},
                    val2: {type: "INTEGER", explicit: true, context: 2, optional: true, index: 0},
                    val3: {type: "INTEGER", explicit: true, context: 3, optional: true, index: 0},
                    val4: {type: "INTEGER", explicit: true, context: 4, optional: true, index: 0},
                    val5: {type: "INTEGER", explicit: true, context: 5, optional: true, index: 0}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("3080A103020101A303020102A4030201040000"));
            var obj = asn.toObject("Test");
            assertNull(obj.val0);
            assertNull(obj.val2);
            assertNull(obj.val5);
            assertNumber(obj.val1);
            assertNumber(obj.val3);
            assertNumber(obj.val4);
        };

        // DEFAULT
        /*
         * 
         */
        ASNTest.prototype.test_ASN_toObject_DEFAULT = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val1: {type: "BOOLEAN", default: true, index: 0},
                    val2: {type: "INTEGER", default: 5, index: 1},
                    val3: {type: "INTEGER", context: 0, default: 3, index: 2, explicit: true}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("3000"));
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.val1);
            assertEquals(true, obj.val1);
            assertNotUndefined(obj.val2);
            assertEquals(5, obj.val2);
            assertNotUndefined(obj.val3);
            assertEquals(3, obj.val3);

            var asn = new trusted.ASN(Hex.toDer("3080010100020104A0030201060000"));
            var obj = asn.toObject("Test");
            assertEquals(false, obj.val1);
            assertEquals(4, obj.val2);
            assertEquals(6, obj.val3);
        };

        // maxOccurs
        /*
         * 
         */
        ASNTest.prototype.test_ASN_toObject_maxOccurs = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                maxOccurs: 1000,
                value: {
                    val1: {type: "INTEGER"}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("30800201010201020201030201040201050000"));
            var obj = asn.toObject("Test");
            assertArray(obj);
        };

        // CHOICE
        ASNTest.prototype.test_ASN_toObject_CHOICE = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    choice: {type: "Choice"}
                }
            };
            trusted.schemas.Choice = {
                type: "CHOICE",
                value: {
                    val1: {type: "BOOLEAN"},
                    val2: {type: "INTEGER"},
                    val3: {type: "BMP_STRING"}
                }
            };

            var asn = new trusted.ASN(Hex.toDer("30800201050000"));
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.choice.val2);

            var asn = new trusted.ASN(Hex.toDer("30800101010000"));
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.choice.val1);

            var asn = new trusted.ASN(Hex.toDer("308030000000"));
            assertException(
                    function() {
                        asn.toObject("Test");
                    },
                    undefined);
        };

        // IMPLICIT
        ASNTest.prototype.test_ASN_toObject_IMPLICIT = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val1: {type: "INTEGER", context: 0}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("3080800201010000"));
            var obj = asn.toObject("Test");
            assertEquals(257, obj.val1);
        };

        // <editor-fold defaultstate="collapsed" desc=" Преобразование ASN данных в Объект ">

        //BOOLEAN
        ASNTest.prototype.test_ASN_toObject_BOOLEAN = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    bool: {type: "BOOLEAN"}
                }
            };
            var asn = new trusted.ASN(DER([48, 3, 1, 1, 1]));
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.bool);
            assertTrue(obj.bool);

            var asn = new trusted.ASN(DER([48, 3, 1, 1, 0]));
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.bool);
            assertFalse(obj.bool);
        };
        //INTEGER
        ASNTest.prototype.test_ASN_toObject_INTEGER = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    num: {type: "INTEGER"}
                }
            };
            var asn = new trusted.ASN(DER([48, 4, 2, 2, 0, 250])); // 1 byte
            var obj = asn.toObject("Test");
            assertNumber(obj.num);
            assertEquals(250, obj.num);

            var asn = new trusted.ASN(DER([48, 4, 2, 2, 1, 1])); // 2 bytes
            var obj = asn.toObject("Test");
            assertNumber(obj.num);
            assertEquals(257, obj.num);

            // до 6 байт возвращает число
            var asn = new trusted.ASN(DER([48, 9, 2, 7, 1, 1, 1, 1, 1, 1, 1])); // 7 bytes
            var obj = asn.toObject("Test");
            assertNumber(obj.num);
            assertEquals(282578800148737, obj.num);

            // Если  >7 байт, то возвращает строку в Hex коде
            var asn = new trusted.ASN(DER([48, 11, 2, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1])); // 9 bytes
            var obj = asn.toObject("Test");
            assertString(obj.num);
            assertEquals("010101010101010101", obj.num);

            var asn = new trusted.ASN(Hex.toDer("30040202FFF6")); // Отрицательное число
            var obj = asn.toObject("Test");
            assertNumber(obj.num);
            assertEquals(-10, obj.num);
        };

        //BIT STRING
        ASNTest.prototype.test_ASN_toObject_BIT_STRING = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val: {type: "BIT_STRING"}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("3004030200FF")); // значени 1 byte, не используемых битов 0
            var obj = asn.toObject("Test");
            assertObject(obj.val);
            assertNotUndefined(obj.val.unusedBit);
            assertNotUndefined(obj.val.encoded);
            assertEquals(0, obj.val.unusedBit);
            assertEquals(255, obj.val.encoded.charCodeAt(0));

            var asn = new trusted.ASN(Hex.toDer("3005030305FFFF")); // значени 2 bytes, не используемых битов 5
            var obj = asn.toObject("Test");
            assertObject(obj.val);
            assertNotUndefined(obj.val.unusedBit);
            assertNotUndefined(obj.val.encoded);
            assertEquals(5, obj.val.unusedBit);
            assertEquals(255, obj.val.encoded.charCodeAt(0));
            assertEquals(255, obj.val.encoded.charCodeAt(1));
        };

        //BIT STRING
        ASNTest.prototype.test_ASN_toObject_OCTET_STRING = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val: {type: "OCTET_STRING"}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("300404020200")); // значени 1 byte, не используемых битов 0
            var obj = asn.toObject("Test");
            assertString(obj.val);
            assertEquals(2, obj.val.charCodeAt(0));
            assertEquals(0, obj.val.charCodeAt(1));
        };

        //OBJECT IDENTIFIER
        ASNTest.prototype.test_ASN_toObject_OBJECT_IDENTIFIER = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val: {type: "OBJECT_IDENTIFIER"}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("300B06092A864886F70D010105"));
            assertBoolean(asn instanceof trusted.ASN);
            var obj = asn.toObject("Test");
            assertEquals("1.2.840.113549.1.1.5", obj.val);
        };

        //SEQUENCE
        /*
         * При построении объекта учитывается порядок структуры. 
         * Значения будут отсортерованы по интексу (index)
         */
        ASNTest.prototype.test_ASN_toObject_SEQUENCE = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    bool: {type: "BOOLEAN", index: 1},
                    num: {type: "INTEGER", index: 0}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("30800201090101010000"));
            assertBoolean(asn instanceof trusted.ASN);
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.num);
            assertNotUndefined(obj.bool);
        };

        //SET
        /*
         * При постоении объекта порядок не важен. Параметры index не учитываются.
         * Элеменыт будут отсортированы в алфавитном порядке.
         */
        ASNTest.prototype.test_ASN_toObject_SET = function() {
            trusted.schemas.Test = {
                type: "SET",
                value: {
                    bool: {type: "BOOLEAN", index: 1},
                    num: {type: "INTEGER", index: 0}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("31800101010201090000"));
            assertBoolean(asn instanceof trusted.ASN);
            var obj = asn.toObject("Test");
            assertNotUndefined(obj.num);
            assertNotUndefined(obj.bool);
        };

        // UTF 8 STRING
        /*
         * Поддерживается кодировка до 3 байтового кодирования символа.
         */
        ASNTest.prototype.test_ASN_toObject_UTF8_STRING = function() {
            trusted.schemas.Test = {
                type: "UTF8_STRING"
            };
            var asn = new trusted.ASN(Hex.toDer("0c0d48656c6c6f2074657374212121"));
            assertBoolean(asn instanceof trusted.ASN);
            var obj = asn.toObject("Test");
            assertEquals("Hello test!!!", obj);
        };

        // NumericString, PrintableString, T61_STRING(TeletexString), 
        // VideotexString, IA5String, ISO64_STRING(VisibleString)
        ASNTest.prototype.test_ASN_toObject_STRING = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    num: {type: "NUMERIC_STRING", index: 0},
                    print: {type: "PRINTABLE_STRING", index: 1},
                    t61: {type: "T61_STRING", index: 2},
                    video: {type: "VIDEOTEX_STRING", index: 3},
                    ia5: {type: "IA5_STRING", index: 4},
                    iso64: {type: "ISO64_STRING", index: 5}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("3077120a313233343536373839301317697427732061207072696e7461626c6520737472696e6714116974277320612054363120737472696e671515697427732061207669646574657820737472696e6716116974277320612049413520737472696e671a136974277320612049534f363420737472696e67"));
            var obj = asn.toObject("Test");
            assertEquals("1234567890", obj.num);
            assertEquals("it's a printable string", obj.print);
            assertEquals("it's a T61 string", obj.t61);
            assertEquals("it's a videtex string", obj.video);
            assertEquals("it's a IA5 string", obj.ia5);
            assertEquals("it's a ISO64 string", obj.iso64);
        };

        // BMPString
        ASNTest.prototype.test_ASN_toObject_BMP_STRING = function() {
            trusted.schemas.Test = {
                type: "BMP_STRING"
            };
            var asn = new trusted.ASN(Hex.toDer("1e1e00490027006d00200042004d005000200073007400720069006e00670021"));
            var obj = asn.toObject("Test");
            assertEquals("I'm BMP string!", obj);
        };

        // UTCTime, GeneralizedTime
        ASNTest.prototype.test_ASN_toObject_TIME = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    ut: {type: "UTC_TIME"},
                    gt: {type: "GENERALIZED_TIME"}
                }
            };
            var asn = new trusted.ASN(Hex.toDer("3080170D3130303231393232343530355A180F32353130303231393232343530355A0000"));
            var obj = asn.toObject("Test");
            assertTrue(obj.ut instanceof Date);
            assertEquals("UTC Year", 110, obj.ut.getYear());
            assertEquals("UTC Month", 2, obj.ut.getMonth()+1);
            assertEquals("UTC Day", 19, obj.ut.getDate());
            assertEquals("UTC Hours", 22, obj.ut.getHours());
            assertEquals("UTC Minutes", 45, obj.ut.getMinutes());
            assertEquals("UTC Seconds", 5, obj.ut.getSeconds());
            assertTrue(obj.gt instanceof Date);
            assertEquals("GT Year", 610, obj.gt.getYear());
            assertEquals("GT Month", 2, obj.gt.getMonth()+1);
            assertEquals("GT Day", 19, obj.gt.getDate());
            assertEquals("GT Hours", 22, obj.gt.getHours());
            assertEquals("GT Minutes", 45, obj.gt.getMinutes());
            assertEquals("GT Seconds", 5, obj.gt.getSeconds());
        };

        // </editor-fold>

        // </editor-fold>

        // <editor-fold defaultstate="collapsed" desc=" fromObject ">

        ASNTest.prototype.test_ASN_fromObject_OPTIONAL = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val1: {type: "INTEGER", optional: true, index: 0},
                    val2: {type: "BOOLEAN", index: 6}
                }
            };

            var obj = {
                val2:true
            };
            var asn = trusted.ASN.fromObject(obj, "Test");
            var new_obj = asn.toObject("Test");
            obj.val1=null;
            assertEquals(obj, new_obj);
        };

        // Array
        ASNTest.prototype.test_ASN_fromObject_ARRAY = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                maxOccurs: 1000,
                value: {
                    val: {type: "INTEGER"}
                }
            };

            var obj = [1, 2, 3, 4, 5, 6, 7, 8, 0, 9];
            var asn = trusted.ASN.fromObject(obj, "Test");
            var new_obj = asn.toObject("Test");
            assertEquals(obj, new_obj);
        };

        // IMPLICIT
        ASNTest.prototype.test_ASN_fromObject_IMPLICIT = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    num: {
                        type: "INTEGER",
                        context: 0
                    }
                }
            };

            var obj = {num: 1000};
            var asn = trusted.ASN.fromObject(obj, "Test");
            var new_obj = asn.toObject("Test");
            assertEquals(obj, new_obj);
        };

        // <editor-fold defaultstate="collapsed" desc=" Преобразование Объекта в ASN структуру">

        // Helpers
        function testPrimitiveValue(v, t) {
            trusted.schemas.Test = {
                type: t
            };

            var obj = v;
            var asn = trusted.ASN.fromObject(obj, "Test");
            obj = asn.toObject("Test");
            assertEquals(v, obj);
        }

        //BOOLEAN
        ASNTest.prototype.test_ASN_fromObject_BOOLEAN = function() {
            testPrimitiveValue(true, "BOOLEAN");
            testPrimitiveValue(false, "BOOLEAN");
        };
        //INTEGER
        ASNTest.prototype.test_ASN_fromObject_INTEGER = function() {
            testPrimitiveValue(0, "INTEGER");
            testPrimitiveValue(127, "INTEGER");
            testPrimitiveValue(128, "INTEGER");
            testPrimitiveValue(520121545, "INTEGER");
            testPrimitiveValue(-10, "INTEGER");
            testPrimitiveValue(-128, "INTEGER");
            testPrimitiveValue(-256, "INTEGER");
            testPrimitiveValue(-100000, "INTEGER");
            testPrimitiveValue("010101010101010101", "INTEGER"); //9 byte hex return hex String
        };

        //BIT STRING
        ASNTest.prototype.test_ASN_fromObject_BIT_STRING = function() {
            trusted.schemas.Test = {
                type: "BIT_STRING"
            };

            var obj = "001111";
            var asn = trusted.ASN.fromObject(obj, "Test");
            obj = asn.toObject("Test");
            assertEquals(2, obj.unusedBit);
            assertEquals(parseInt("00111111", 2).toString(16), DerToHex(obj.encoded));
        };

        //BIT STRING
        ASNTest.prototype.test_ASN_fromObject_OCTET_STRING = function() {
            //testPrimitiveValue("abracadabra", "OCTET_STRING");
        };

        //OBJECT IDENTIFIER
        ASNTest.prototype.test_ASN_fromObject_OBJECT_IDENTIFIER = function() {
            testPrimitiveValue("1.2.123.256.25454.0.0.1", "OBJECT_IDENTIFIER");
            testPrimitiveValue("0.2.123.256.25454.0.0.1", "OBJECT_IDENTIFIER");
            testPrimitiveValue("2.2.123.256.25454.0.0.1", "OBJECT_IDENTIFIER");
            // неверный OID первая цифра может быть только 0 1 2.
            assertException(function() {
                testPrimitiveValue("3.2.123.256.25454.0.0.1", "OBJECT_IDENTIFIER");
            });
            // неверный OID
            assertException(function() {
                testPrimitiveValue("1.2.", "OBJECT_IDENTIFIER");
            });
            assertException(function() {
                testPrimitiveValue("Wrong value", "OBJECT_IDENTIFIER");
            });
        };

        //SEQUENCE
        /*
         * При построении объекта учитывается порядок структуры. 
         * Значения будут отсортерованы по интексу (index)
         */
        ASNTest.prototype.test_ASN_fromObject_SEQUENCE = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    bool: {type: "BOOLEAN", index: 1},
                    num: {type: "INTEGER", index: 0}
                }
            };

            var obj = {bool: true, num: -10};
            var asn = trusted.ASN.fromObject(obj, "Test");
            obj = asn.toObject("Test");
            assertEquals(true, obj.bool);
            assertEquals(-10, obj.num);
        };

        //SET
        /*
         * При постоении объекта порядок не важен. Параметры index не учитываются.
         * Элеменыт будут отсортированы в алфавитном порядке.
         */
        ASNTest.prototype.test_ASN_fromObject_SET = function() {
            trusted.schemas.Test = {
                type: "SET",
                value: {
                    bool: {type: "BOOLEAN", index: 1}, // для SET порядок не важен index опускается
                    num: {type: "INTEGER", index: 0}
                }
            };
            var obj = {bool: true, num: -10};
            var asn = trusted.ASN.fromObject(obj, "Test");
            obj = asn.toObject("Test");
            assertEquals(true, obj.bool);
            assertEquals(-10, obj.num);
        };

        // UTF8 STRING
        /*
         * Поддерживается кодировка до 3 байтового кодирования символа.
         */
        ASNTest.prototype.test_ASN_fromObject_UTF8_STRING = function() {
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "UTF8_STRING");
            //testPrimitiveValue("Проверчное сообщение 1234567890 !@#$%^&*()","UTF8_STRING");
            // jsTestDriver не поддерживает кирилицу. Нужен пропатченный модуль.
        };

        // NumericString, PrintableString, T61_STRING(TeletexString), 
        // VideotexString, IA5String, ISO64_STRING(VisibleString)
        ASNTest.prototype.test_ASN_fromObject_STRING = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    num: {type: "NUMERIC_STRING", index: 0},
                    print: {type: "PRINTABLE_STRING", index: 1},
                    t61: {type: "T61_STRING", index: 2},
                    video: {type: "VIDEOTEX_STRING", index: 3},
                    ia5: {type: "IA5_STRING", index: 4},
                    iso64: {type: "ISO64_STRING", index: 5}
                }
            };
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "NUMERIC_STRING");
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "PRINTABLE_STRING");
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "T61_STRING");
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "VIDEOTEX_STRING");
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "IA5_STRING");
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "ISO64_STRING");
        };

        // BMPString
        ASNTest.prototype.test_ASN_fromObject_BMP_STRING = function() {
            testPrimitiveValue("Test value 1234567890 !@#$%^&*()", "BMP_STRING");
        };

        // UTCTime, GeneralizedTime
        ASNTest.prototype.test_ASN_fromObject_TIME = function() {
            var date = new Date();
            testPrimitiveValue(date, "UTC_TIME");
            date.setFullYear(2100);
            testPrimitiveValue(date, "GENERALIZED_TIME");
        };

        // </editor-fold>

        // </editor-fold>

        // <editor-fold defaultstate="collapsed" desc=" encode ">
        ASNTest.prototype.test_ASN_encode = function() {
            trusted.schemas.Test = {
                type: "SEQUENCE",
                value: {
                    val: {type: "INTEGER"}
                }
            };

            var obj = {val: 1000};
            var asn = trusted.ASN.fromObject(obj, "Test");
            asn = new trusted.ASN(asn.encode());
            var new_obj = asn.toObject("Test");
            assertEquals(obj, new_obj);
        };
        // </editor-fold>
    }

}
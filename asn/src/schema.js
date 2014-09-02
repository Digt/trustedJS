
// <editor-fold defaultstate="collapsed" desc=" Constants ">
var ASN1TagClass = {
    UNIVERSAL: 0x00,
    APPLICATION: 0x01,
    CONTEXT: 0x02,
    PRIVATE: 0x03
};
var ASN1TagType = {
    EOC: 0x00,
    BOOLEAN: 0x01,
    INTEGER: 0x02,
    BIT_STRING: 0x03,
    OCTET_STRING: 0x04,
    NULL: 0x05,
    OBJECT_IDENTIFIER: 0x06,
    OBJECT_DESCRIPTOR: 0x07,
    EXTERNAL: 0x08,
    REAL: 0x09,
    ENUMERATED: 0x0A,
    EMBEDDED_PDV: 0x0B,
    UTF8_STRING: 0x0C,
    SEQUENCE: 0x10,
    SET: 0x11,
    NUMERIC_STRING: 0x12,
    PRINTABLE_STRING: 0x13,
    T61_STRING: 0x14,
    VIDEOTEX_STRING: 0x15,
    IA5_STRING: 0x16,
    UTC_TIME: 0x17,
    GENERALIZED_TIME: 0x18,
    GRAPHIC_STRING: 0x19,
    ISO64_STRING: 0x1A, //VISIBLE_STRING
    GENERAL_STRING: 0x1B,
    UNIVERSAL_STRING: 0x1C,
    BMP_STRING: 0x1E
};
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc=" Basic Schemas ">
(function() {
    schemas = {};
    trusted.objEach(ASN1TagType, function(prop, propName) {
        schemas[propName] = {
            type: propName,
            tag: {
                constructed: (prop === ASN1TagType.SEQUENCE || prop === ASN1TagType.SET) ? true : false,
                number: prop,
                class: ASN1TagClass.UNIVERSAL
            },
            isSimpleType: true
        };
    });
    schemas.SEQUENCE.value = {};
    schemas.SET.value = {};
    schemas.CHOICE = {
        isChoice: true,
        explicit:true,
        type: "CHOICE",
        isSimpleType: true,
        value: {}
    };
    schemas.ANY = {
        type: "ANY",
        isAny: true,
        isSimpleType: true,
        value: {}
    };
})();
// </editor-fold>

function Schema() {
    this.value = null;

    function init(arg) {
        switch (arg.length) {
            case 0:
                throw "Schema.new: Параметр не может быть undefined."
            case 1:
                if (trusted.isString(arg[0])) {
                    this.value = compile(arg[0]);
                    break;
                }
                throw "Schema.new: Неверный тип параметра."
            default:
                throw "Schema.new: Неверное количество параметров."
        }
    }

    function getSchema(s) {
        if (trusted.isString(s)) {
            if (s in schemas) {
                s = schemas[s];
            } else
                throw "Schema '" + s + "' was not found.";
        }
        if (trusted.isObject(s)) {
            verify(s);
            return s;
        } else
            throw "Schema has wrong data type.";
    }

    function compile(s) {
        s = getSchema(s);
        if (("type" in s) && (!s.isSimpleType)) {
            var ns = compile(s.type);
            trusted.objUnion(s, ns);
        }
        if ("value" in s) {
            trusted.objEach(s.value, function(o, n) {
                trusted.objUnion(o, compile(o));
                o.name = n;
            });
        }
        return s;
    }

    // Элкменты схемы не могут иметь атрибуты отличные от указанных
    var regWords = {
        value: null,
        type: null,
        context: null,
        default: null,
        minOccurs: null,
        maxOccurs: null,
        optional: null,
        index: null,
        constructed: null,
        isSimpleType: null,
        isChoice: null,
        isAny: null,
        tag: null,
        name: null,
        implicit: null,
        explicit: null,
        length:null
    };

    function verify(schema) {
        // Каждый элемент схемы должен иметь атрибут 'type'
        if (!schema.hasOwnProperty("type"))
            throw "Schema '" + schema.name + "' does not have attribute 'type'.";
        // Элементы типа SEQUENCE, SET, CHOICE, ANY дожны иметь атрибут 'value'
        if ((schema.hasOwnProperty("CHOICE") ||
                schema.hasOwnProperty("ANY") ||
                (schema.hasOwnProperty("SEQUENCE") || (schema.tag_class === 0 && schema.tag_number === 16)) ||
                (schema.hasOwnProperty("SET") || (schema.tag_class === 0 && schema.tag_number === 17))) &&
                !schema.hasOwnProperty("value")
                )
            throw "Schema '" + schema.name + "' does not have attribute 'value'.";
        if (("value" in schema) && !trusted.isObject(schema.value))
            throw "Schema '" + schema.name + "' value must be Object.";
        var keys = Object.keys(schema);
        for (var i = 0; i < keys.length; i++)
            if (!(keys[i] in regWords))
                throw "Schema '" + schema.name + "' has wrong value '" + keys[i] + "'";
        trusted.objEach(schema.value, function(v, n) {
            if (!trusted.isObject(v))
                throw "Schema value '" + n + "' must be Object.";
            verify(v);
        });
        if (schema.isSimpleType)
            return;
    }

    init.call(this, arguments);
}

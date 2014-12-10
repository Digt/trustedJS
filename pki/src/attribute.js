function Attribute() {
    var _obj;

    //properties
    this.__proto__ = {
        get type() {
            return new trusted.PKI.OID(_obj.type);
        },
        get values() {
            return _obj.values;
        }
    };

    this.__proto__.toObject = function() {
        if (_obj !== undefined)
            return _obj;
    };

    function init(args) {
        _obj = objFromBuffer(args[0], "Attribute");
    }

    init.call(this, arguments);
}

Attribute.create = function(type, values, schema) {
    if (trusted.isString(type))
        type = new trusted.PKI.OID(type);
    if (!trusted.isArray(values))
        values = [values];
    var vs = [];
    for (var i in values) {
        if (values[i].type !== "Buffer")
            throw "Attribute.create: Value must be type of Buffer";
        vs.push(trusted.ASN.fromObject(values[i], schema).blob());
    }
    var attr = {
        type: type.value,
        values: vs
    };
    return trusted.ASN.fromObject(attr, "Attribute").blob();
};


trusted.PKI.Attribute = Attribute;
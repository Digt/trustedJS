function PKCS7() {
    var obj, oid;
    this.__proto__ = {
        set OID(v) {
            if (trusted.isString(v))
                v = new trusted.PKI.OID(v);
            if (oid === undefined || v.value !== oid.value) {
                oid = v;
            }
        },
        get OID() {
            if (oid === undefined && obj!==undefined) {
                oid = new trusted.PKI.OID(obj.contentType);
            }
            return oid;
        },
        get content() {
            if (obj === undefined)
                return null;
            return obj.content;
        },
        get type(){
            if (obj === undefined)
                return null;
            for (var k in trusted.PKI.PKCS7Types)
                if (trusted.PKI.PKCS7Types[k]===obj.contentType)
                    return k;
            return "Unknown type";
        },
        get value(){
            if (obj === undefined)
                return null;
            if (this.type === "Unknown type")
                throw "Unknown type";
            var s = this.type.charAt(0).toUpperCase()+this.type.substring(1); // get schema name
            return (new trusted.ASN(this.content)).toObject(s);
        }
    };

    this.__proto__.toObject = function() {
        var o = {
            contentType: this.OID.value
        };
        if (this.content!==null)
            o.content = this.content;
        return o;
    };

    function init(v) {
        if (v === undefined)
            return;
        v = objFromBuffer(v, "ContentInfo");
        if (!(trusted.isObject(v) && ("contentType" in v && "content" in v)))
            "PKCS7.new: Параметр имеет не верный формат.";
        obj = v;
    }

    init.call(this, arguments[0]);

}

PKCS7.create = function(type, data){
    var oid = null;
    if (trusted.PKI.OID.test(type))
        for (var i in trusted.PKI.PKCS7Types)
            if (trusted.PKI.PKCS7Types[i]===type){
                type = i;
                break;
            }
    if (!(type in trusted.PKI.PKCS7Types))
        throw ("PKCS7.create: Unknown PKCS7 type");
    
    var pkcs7 = {
        contentType: trusted.PKI.PKCS7Types[type],
        content: data
    };
    return trusted.ASN.fromObject(pkcs7, "ContentInfo").blob();
};

PKCS7.createData = function(data){
    data = trusted.ASN.fromObject(data, "OCTET_STRING").blob();
    return PKCS7.create("data", data);
};

trusted.PKI.PKCS7 = PKCS7;

trusted.PKI.PKCS7Types = {
    "data": "1.2.840.113549.1.7.1",
    "signedData": "1.2.840.113549.1.7.2",
    "envelopedData": "1.2.840.113549.1.7.3",
    "signedAndEnvelopedData": "1.2.840.113549.1.7.4",
    "digestedData": "1.2.840.113549.1.7.5",
    "encryptedData": "1.2.840.113549.1.7.6"
};
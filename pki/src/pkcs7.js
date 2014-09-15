function PKCS7() {
    var obj, oid;
    this.__proto__ = {
        get OID() {
            if (oid === undefined) {
                oid = new trusted.PKI.OID(obj.contentType);
            }
            return oid;
        },
        get content() {
            return obj.content;
        }
    };

    this.__proto__.toObject = function() {
        var o = {
            contentType: this.OID.value,
            content: this.content
        };
        return o;
    };

    function init(v) {
        if (v === undefined)
            throw "PKCS7.new: Параметр не может быть Undefined."
        if (trusted.isString(v)) {
            var asn = new trusted.ASN(v);
            v = asn.toObject("ContentInfo");
        }
        if (!(trusted.isObject(v) && ("contentType" in v && "content" in v)))
            "PKCS7.new: Параметр имеет не верный формат.";
        obj = v;
    }

    init.call(this, arguments[0]);

}
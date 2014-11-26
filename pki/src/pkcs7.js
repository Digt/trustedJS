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
        if (trusted.isString(v)) {
            if (v in trusted.PKI.PKCS7Types) {
                oid = new trusted.PKI.OID(trusted.PKI.PKCS7Types[v]);
                return;
            } else {
                v = objFromBuffer(v, "ContentInfo");
            }
        }
        if (!(trusted.isObject(v) && ("contentType" in v && "content" in v)))
            "PKCS7.new: Параметр имеет не верный формат.";
        obj = v;
    }

    init.call(this, arguments[0]);

}
trusted.PKI.PKCS7 = PKCS7;

trusted.PKI.PKCS7Types = {
    "data": "1.2.840.113549.1.7.1",
    "signedData": "1.2.840.113549.1.7.2",
    "envelopedData": "1.2.840.113549.1.7.3",
    "signedAndEnvelopedData": "1.2.840.113549.1.7.4",
    "digestedData": "1.2.840.113549.1.7.5",
    "encryptedData": "1.2.840.113549.1.7.6"
};
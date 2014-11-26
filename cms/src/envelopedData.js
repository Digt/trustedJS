function EnvelopedData() {
    var obj, ed, cache;

    this.__proto__ = {
        set content(v) {
            if (!trusted.isString()) {
                "EnvelopedData.content SET: Значение должно быть Строкой.";
            }
            if (cache.content !== v) {
                refreshVars();
                cache.content = v;
            }
        },
        get content() {
            if (cache.content === undefined) {
                cache.content = null;
                try {
                    // if content is array of OCTET_STRING
                    var asn = new trusted.ASN(Hex.toDer("2480") + obj.encryptedContentInfo.encryptedContent + Hex.toDer("0000"));
                    cache.content = asn.toObject("DataContent").join("");
                }
                catch (e) {
                    cache.content = obj.encryptedContentInfo.encryptedContent;
                }
            }
            return cache.content;
        },
        get recipients() {
            if (cache.recipients === undefined || cache.recipients === null) {
                cache.recipients = [];
                if ("recipientInfos" in obj)
                    for (var i = 0; i < obj.recipientInfos.length; i++) {
                        cache.recipients.push(
                                new Recipient(obj.recipientInfos[i])
                                );
                    }
            }
            return cache.recipients;
        }
    };
    
    this.__proto__.encrypt = function(algorithm, recipients){
        // Generate symmetric Key
    };

    function init(args) {
        refreshVars();
        switch (args.length) {
            case 0:
                break;
            default:
                var v = args[0];
                if (trusted.isString(v)) {
                    try {
                        v = new PKCS7(v);
                    }
                    catch (e) {
                        throw "EnvelopedData.new: ASN пакет не соответствует структуре ASN PKCS7.";
                    }
                    if (v.OID.value !== "1.2.840.113549.1.7.3")
                        throw "EnvelopedData.new: Тип PKCS7 не является EncryptedData.";
                    v = objFromBuffer(v.content, "EnvelopedData");
                }
                obj = v;
                console.log("EnvelopedData:", obj);
        }
    }

    function refreshVars() {
        obj = undefined;
        cache = {};
    }

    init.call(this, arguments);
}
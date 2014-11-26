function Recipient() {
    var obj, cache;
    this.__proto__ = {
        //keyEncryptionAlgorithm
        get algorithm() {
            if (cache.alg === undefined){
                cache.alg = null;
                cache.alg = new trusted.PKI.Algorithm(obj.keyEncryptionAlgorithm);
            }
            return cache.alg;
        },
        get encryptedKey() {
            return obj.encryptedKey;
        },
        get certificateID() {
            if (cache.certID === null || cache.certID === undefined)
                if ("issuerAndSerialNumber" in obj) {
                    cache.certID = new CertID(
                            new trusted.PKI.Name(obj.issuerAndSerialNumber.issuer),
                            obj.issuerAndSerialNumber.serialNumber);
                }
                else {
                    cache.certID = new CertID(this.certificate);
                }
            return cache.certID;
        },
        get version() {
            if (cache.v === undefined) {
                cache.v = 0; //it should be 0 for this version
                if (obj.version !== undefined)
                    cache.v = obj.version;
            }
            return cache.v;
        }
    };
    
    this.__proto__.encryptKey=function(){
        var _this = this;
        
    };

    function refreshVars() {
        obj = {};
        cache = {cert: null, certID: null};
    }

    function init(args) {
        refreshVars.call(this);
        v = objFromBuffer(v, "RecipientInfo");
        if (!(trusted.isObject(args[0])))
            throw "Recipient.new: Параметр имеет неверный формат.";
        if (trusted.isObject(args[1])){
            if (args[1].type !== "Certificate")
                throw "Recipient.new: Параметр certificate должен быть Certificate"
            cache.cert = args[1];
        }
        obj = args[0];
    }

    init.call(this, arguments);
}

trusted.PKI.KeyUsageFlags = {
    DigitalSignature: 0x01,
    NonRepudiation: 0x02,
    KeyEncipherment: 0x04,
    DataEncipherment: 0x08,
    KeyAgreement: 0x10,
    KeyCertSign: 0x20,
    CRLSign: 0x40,
    EncipherOnly: 0x80,
    DecipherOnly: 0x100
};

(function() {

    function KeyUsage() {
        var obj, ku;
        this.__proto__ = {
            set keyUsage(v) {
            },
            get keyUsage() {
                if (ku === undefined) {
                    ku = obj.toNumber();
                }
                return ku;
            },
            set value(v){},
            get value(){
                return this.keyUsage;
            }
        };
        
        this.__proto__.toObject = function(){
            return {keuUsage:new BitString(this.keyUsage)};
        };

        function createIsFunctions(v) {
            var keys = Object.keys(v);
            for (var i = 0; i < keys.length; i++) {
                var index = i; // Создаем копию i, иначе все функции будут использовать i = keys.
                this.__proto__["is" + keys[index]] = new Function("return ((this.keyUsage&" + v[keys[index]] + ")>0)?true:false;");
            }
        }

        createIsFunctions.call(this, trusted.PKI.KeyUsageFlags);

        this.__proto__.toObject = function() {
            return new BitString(this.keyUsage);
        };

        function init(v) {
            if (v === undefined)
                throw "KeyUsage.new: parameter can not be undefined."
            if (typeof (v) === "number") {
                obj = new BitString(v);
                return;
            }
            if (typeof (v) === "string")
                v = (new trusted.ASN(v)).toObject("KeyUsage");
            if (!(trusted.isObject(v) &&
                    v.__proto__.hasOwnProperty("unusedBit") &&
                    v.__proto__.hasOwnProperty("encoded")))
                throw "KeyUsage.new: parameter is not valid."

            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.KeyUsage = KeyUsage;
})();


(function() {
    function PrivateKeyUsagePeriod() {
        var obj;

        //location
        Object.defineProperty(this.__proto__, "notBefore", {
            get: function() {
                if (obj.notBefore === undefined)
                    return null;
                return obj.notBefore;
            },
            set: function(v) {
            },
            enumerable: true,
            configurable: true
        });
        //  method
        Object.defineProperty(this.__proto__, "notAfter", {
            get: function() {
                if (obj.notAfter === undefined)
                    return null;
                return obj.notAfter;
            },
            set: function(v) {
            },
            enumerable: true,
            configurable: true
        });

        this.__proto__.toObject = function() {
            var o = {};
            
            void this.notBefore!==null?o.notBefore=this.notBefore:null;
            void this.notAfter!==null?o.notAfter=this.notAfter:null;
            return o;
        };

        //method

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "PrivateKeyUsagePeriod.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("PrivateKeyUsagePeriod");
            if (!trusted.isObject(v) && !("notBefore" in v && "notAfter" in v))
                throw "PrivateKeyUsagePeriod.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }


    trusted.PKI.PrivateKeyUsagePeriod = PrivateKeyUsagePeriod;
})();



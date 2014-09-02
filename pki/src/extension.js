
(function() {
    function Extension() {
        var obj;

        this.__proto__ = {
            set critical(v) {
            },
            get critical() {
                return (obj === undefined) ? undefined : obj.critical;
            },
            set extnID(v) {
            },
            get extnID() {
                return (obj === undefined) ? undefined : new trusted.PKI.OID(obj.extnID);
            },
            set extnValue(v) {
            },
            get extnValue() {
                return (obj === undefined) ? undefined : obj.extnValue;
            },
            set value(v){},
            get value(){
                return this.extnValue;
            },
            set OID(v){},
            get OID(){
                return this.extnID;
            }
        };
        
        this.__proto__.toObject = function(){
            var o = {};
            o.critical = this.critical;
            o.extnId = this.extnID;
            o.extnValue = this.extnValue;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "Extension.new: parameter can not be undefined."
            if (typeof(v)==="string")
                v = (new trusted.ASN(v)).toObject("Extension");
            if (!(typeof (v) === "object" &&
                    v.hasOwnProperty("critical") &&
                    v.hasOwnProperty("extnID") &&
                    v.hasOwnProperty("extnValue")))
                throw "Extension.new: parameter is not valid."
            obj = v;
        }

        init.call(this,arguments[0]);
    }

    trusted.PKI.Extension = Extension;
})();



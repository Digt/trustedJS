
(function() {
    function Extension() {
        var obj;

        this.__proto__ = {
            set critical(v) {
            },
            get critical() {
                return (obj === undefined) ? undefined : obj.critical;
            },
            get value() {
                return (obj === undefined) ? undefined : obj.extnValue;
            },
            get OID() {
                return (obj === undefined) ? undefined : new trusted.PKI.OID(obj.extnID);
            },
            get type(){
                return "Extension";
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.critical = this.critical;
            o.extnID = this.OID.value;
            o.extnValue = this.value;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "Extension.new: parameter can not be undefined."
            v = objFromBuffer(v, "Extension");
            if (!(trusted.isObject(v) &&
                    "critical" in v &&
                    "extnID" in v &&
                    "extnValue" in v))
                throw "Extension.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.Extension = Extension;
})();



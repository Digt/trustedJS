(function(undefined) {
    
    function OID() {
        var _value;

        this.name = null;
        this.comment = null;

        this.__proto__ = {
            set value(v) {
                if (!OID.test(v))
                    throw "OID.setValue: Wrong value. (" + v + ")";
                if (v !== _value) {
                    _value = v;
                    var oid = trusted.oids[v];
                    if (oid !== undefined) {
                        this.name = oid.d;
                        this.comment = oid.c;
                    } else {
                        this.name = v;
                        this.comment = "";
                    }
                }
            },
            get value() {
                return _value;
            },
            get type(){
                return "OID";
            }
        };

        this.__proto__.toString = function() {
            var s = this.name;
            if (s !== this.value) {
                s += " (" + this.value + ")";
            }
            return s;
        };

        this.__proto__.toObject = function() {
            return this.value;
        };


        //constructor
        switch (arguments.length) {
            case 1:
                this.value = arguments[0];
        }

    }
    
    OID.test = function(v){
        var oid_regex = /^[0-2](\.\d+)+$/g;
        if (typeof (v) !== "string")
                return false;
            
        return oid_regex.test(v);
    };

    trusted.PKI.OID = OID;
})();
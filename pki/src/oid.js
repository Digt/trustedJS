(function(undefined) {
    function OID() {
        var _value;
        
        this.name=null;
        this.comment=null;

        this.__proto__ = {
            set value(v) {
                if (!checkValue(v))
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
            get value(){
                return _value;
            }
        };
        
        this.__proto__.toString=function(){
            return this.name;
        };
        
        this.__proto__.toObject=function(){
            return this.value;
        };

        function checkValue(v) {
            if (typeof (v) !== "string")
                return false;
            var regex = /^[0-2](\.\d+)+$/g;
            return regex.test(v);
        }

        //constructor
        switch (arguments.length) {
            case 1:
                this.value = arguments[0];
        }
        
    }

    trusted.PKI.OID = OID;
})();
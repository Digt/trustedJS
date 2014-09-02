// класс пока не используется
trusted.BitString=function(){
    var obj;
    
    this.__proto__={
        set unusedBit(v){
        },
        get unusedBit(){
            return obj.unusedBit;
        }
    };
    
    function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "BitString.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("BIT_STRING");
            }
            if (!((trusted.isObject(v)) && ("unusedBit" in v) && ("encoded" in v)))
                throw "BitString.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
};



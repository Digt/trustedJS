if (window.trusted === undefined)
    window.trusted = {};

trusted.PKI = {};

function getExtnByOID(extns, oid) {
    if (trusted.isString(oid))
        oid = new trusted.PKI.OID(oid);
    if (!(trusted.isObject(oid)) || oid === undefined)
        throw "Certificate.getExtnByOID: Параметр oid имеет неверное значение";
    var res = null;
    for (var i = 0; i < extns.length; i++) {
        if (extns[i].OID.value === oid.value)
            return extns[i];
    }
    return res;
}

// private
function Time() {
    var obj;
    function init(v){
        if (v===undefined)
            throw "Time.new: Парметр не может быть Undefined";
        if (trusted.isString(v)){
            var asn = new trusted.ASN(v);
            v = asn.toObject("Time");
        }
        if (!(trusted.isObject(v) && ("utcTime" in v || "generalTime" in v )))
            throw "Time.new: Парметр имеет неверный формат";
        obj = v;            
    }
    
    init.call(this, arguments[0]);
    
    if ("utcTime" in obj)
        obj = obj.utcTime;
    else
        obj = obj.generalTime;
    return  obj;
};
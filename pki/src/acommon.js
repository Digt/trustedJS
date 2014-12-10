if (window.trusted === undefined)
    window.trusted = {};

trusted.PKI = {};

trusted.ExportType = {
  binary: 1,  
  hex: 2,  
  pem: 3  
};

/**
 * Возвращает объект полученный из буфера по заданной схеме.
 * @param {type} buf Буфер. Параметр может быть двух типов - бинарная строка и Буфер.
 * @param {type} schemaName Имя схемы.
 * @returns {Object}
 */
function objFromBuffer(buf, schemaName){
    if (trusted.isString(buf))
        buf = new trusted.Buffer(buf, "binary");
    if (buf.type!=="Buffer" && !buf.__proto__.hasOwnProperty("toArrayBuffer"))
        return buf;
    var asn = new trusted.ASN(buf);
    var obj = asn.toObject(schemaName);
    return obj;
}

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
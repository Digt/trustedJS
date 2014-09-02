window.encoder = {};

window.encoder.ExtnKeyUsage = function(eku) {
    if (eku === undefined)
        throw "encoder.ExtnKeuUsage: Задан не верный параметр.";
    var oids = [];
    for (var i = 0; i < eku.anyExtendedKeyUsage.length; i++) {
        oids.push(eku.anyExtendedKeyUsage[i].value);
    }
    return trusted.ASN.fromObject(oids, "ExtKeyUsageSyntax");
};

window.encoder.RDNAttribute = function(v) {
    if (v === undefined)
        throw "encoder.RDNAttribute: Задан не верный параметр.";
    var obj = {
        type: v.type.value,
        value: v.value
    };
    return trusted.ASN.fromObject(obj, "AttributeTypeAndValue");
};

window.encoder.RDN = function(v) {
    if (v === undefined)
        throw "encoder.RDN: Задан не верный параметр.";
    var atts = [];
    for (var i = 0; i < v.attributes.length; i++) {
        atts.push({
            type: v.attributes[i].type.value,
            value: v.attributes[i].value
        });
    }
    return trusted.ASN.fromObject(atts, "RelativeDistinguishedName");
};

window.encoder.Name = function(v) {
    if (v === undefined)
        throw "encoder.Name: Задан не верный параметр.";
    var RDNs = [];
    for (var i = 0; i < v.RDNs.length; i++) {
        var atts = [];
        for (var j = 0; j < v.RDNs[i].attributes.length; j++) {
            atts.push({
                type: v.RDNs[i].attributes[j].type.value,
                value: v.RDNs[i].attributes[j].value
            });
        }
        RDNs.push(atts);
    }
    var obj = {rdnSequence: RDNs};
    return trusted.ASN.fromObject(obj, "Name");
};


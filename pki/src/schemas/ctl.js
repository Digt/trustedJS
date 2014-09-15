trusted.schemas.CertificateTrustList = {
    type: "SEQUENCE",
    value: {
        version: {type: "Version", default: 1, index: 0},
        subjectUsage: {type: "SEQUENCE", maxOccurs: MAX, value: {v: {type: "OBJECT_IDENTIFIER"}}, index:1},
        listIdentifier:{type:"OCTET_STRING",optional:true, index: 2},
        sequenceNumber:{type: "INTEGER", optional:true, index: 3},
        thisUpdate:{type:"Time", index: 4},
        nextUpdate:{type:"Time", optional: true, index: 5},
        subjectAlgorithm:{type:"AlgorithmIdentifier", index: 6},
        subjects:{type:"CTLSubjects", optional: true, index: 7},
        extensions:{type:"Extensions", optional:true, explicit: true, index: 8}
    }
};

trusted.schemas.CTLSubjects= {
    type:"SEQUENCE",
    maxOccurs: MAX,
    value:{
        v:{
            type:"SEQUENCE",
            value:{
                subjectIdentifier:{type:"OCTET_STRING", index:0},
                attributes:{type:"Attributes", optional: true, index: 1}
            }
        }
    }
};
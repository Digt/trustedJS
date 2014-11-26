
(function() {

    function SubjectKeyIdentifier() {
        var obj;
        this.__proto__ = {
            set keyIdentifier(v) {
            },
            get keyIdentifier() {
                return obj;
            }
        };

        function init(v) {
            if (v === undefined)
                throw "SubjectKeyIdentifier.new: parameter can not be undefined."
            v = objFromBuffer(v, "SubjectKeyIdentifier");

            obj = Der.toHex(v);
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.SubjectKeyIdentifier = SubjectKeyIdentifier;
})();


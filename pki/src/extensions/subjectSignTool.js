(function() {
    function SubjectSignTool() {
        var obj;

        this.__proto__ = {
            set subject(v) {
            },
            get subject() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            return this.subject;
        };

        this.__proto__.toString = function() {
            return 'Extension SubjectSignTool(1.2.643.100.112):' + this.subject;
        };

        /**
         * @param {type} v Parameter
         * @param {type} f DER flas. True is string is DER, else False. Default True
         * @returns {undefined}
         */
        function init(v, f) {
            if (v === undefined) {
                throw "SubjectSignTool.new: parameter can not be undefined."
            }

            if (f === undefined)
                f = true;
            if (trusted.isString(v) && f) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("SubjectSignTool");
            }
            if (!trusted.isString(v))
                throw "SubjectSignTool.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0],arguments[1]);
    }

    trusted.PKI.SubjectSignTool = SubjectSignTool;
})();
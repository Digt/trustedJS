// Base64 JavaScript decoder
// Copyright (c) 2008-2014 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
(function(undefined) {
    "use strict";

    var Base64 = {},
            decoder;

    Base64.decode = function(a) {
        var i;
        if (decoder === undefined) {
            var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                    ignore = "= \f\n\r\t\u00A0\u2028\u2029";
            decoder = [];
            for (i = 0; i < 64; ++i)
                decoder[b64.charAt(i)] = i;
            for (i = 0; i < ignore.length; ++i)
                decoder[ignore.charAt(i)] = -1;
        }
        var out = [];
        var bits = 0, char_count = 0;
        for (i = 0; i < a.length; ++i) {
            var c = a.charAt(i);
            if (c == '=')
                break;
            c = decoder[c];
            if (c == -1)
                continue;
            if (c === undefined)
                throw 'Illegal character at offset ' + i;
            bits |= c;
            if (++char_count >= 4) {
                out[out.length] = (bits >> 16);
                out[out.length] = (bits >> 8) & 0xFF;
                out[out.length] = bits & 0xFF;
                bits = 0;
                char_count = 0;
            } else {
                bits <<= 6;
            }
        }
        switch (char_count) {
            case 1:
                throw "Base64 encoding incomplete: at least 2 bits missing";
            case 2:
                out[out.length] = (bits >> 10);
                break;
            case 3:
                out[out.length] = (bits >> 16);
                out[out.length] = (bits >> 8) & 0xFF;
                break;
        }
        var der = '';
        for (var i = 0; i < out.length; i++) {
            der += String.fromCharCode(out[i]);
        }
        return out;
    };

    Base64.re = /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
    Base64.unarmor = function(a) {
        var m = Base64.re.exec(a);
        if (m) {
            if (m[1])
                a = m[1];
            else if (m[2])
                a = m[2];
            else
                throw "RegExp out of sync";
        }
        return Base64.decode(a);
    };

    Base64.toHex = function(str) {
        return Der.toHex(Base64.toDer(str));
    };
    Base64.toDer = function(str) {
        var nums;
        if (Base64.re.test(str))
            nums = Base64.unarmor(str);
        else
            nums = Base64.decode(str);
        var s = "";
        for (var i = 0; i < nums.length; i++)
            s += String.fromCharCode(nums[i]);
        return s;
    };

    var tableStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var table = tableStr.split("");
    function btoa(bin) {
        for (var i = 0, j = 0, len = bin.length / 3, base64 = []; i < len; ++i) {
            var a = bin.charCodeAt(j++), b = bin.charCodeAt(j++), c = bin.charCodeAt(j++);
            if ((a | b | c) > 255)
                throw new Error("String contains an invalid character");
            base64[base64.length] = table[a >> 2] + table[((a << 4) & 63) | (b >> 4)] +
                    (isNaN(b) ? "=" : table[((b << 2) & 63) | (c >> 6)]) +
                    (isNaN(b + c) ? "=" : table[c & 63]);
        }
        return base64.join("");
    }



    Base64.fromHex = function(str) {
        return btoa(String.fromCharCode.apply(null,
                str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
                );
    };

// exports

    window.Base64 = Base64;

})();

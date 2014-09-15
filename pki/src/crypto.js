trusted.CryptoStatus = {
    Done: 0,
    Pending: 1,
    Error: 2
};

Object.defineProperty(window.trusted, "Crypto", {
    get: function() {
        if ("crypto" in window)
            return  window.crypto.subtle;
        else if ("msCrypto" in window)
            return  window.msCrypto.subtle;
        else
            throw "Crypto: Your browser doesn't have crypto module."
    }
});






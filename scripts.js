if (typeof (module) !== 'undefined' && typeof (exports) !== 'undefined') {
    module.exports = OAuth;
    var CryptoJS = require("crypto-js");
}

/**
 * Constructor
 * @param {Object} opts consumer key and secret
 */
function OAuth(opts) {
    if (!(this instanceof OAuth)) {
        return new OAuth(opts);
    }

    if (!opts) {
        opts = {};
    }

    if (!opts.consumer) {
        throw new Error('consumer option is required');
    }

    this.consumer = opts.consumer;
    this.signature_method = opts.signature_method || 'HMAC-SHA1';
    this.nonce_length = opts.nonce_length || 32;
    this.version = opts.version || '1.0';
    this.parameter_seperator = opts.parameter_seperator || ', ';

    if (typeof opts.last_ampersand === 'undefined') {
        this.last_ampersand = true;
    } else {
        this.last_ampersand = opts.last_ampersand;
    }

    switch (this.signature_method) {
        case 'HMAC-SHA1':
            this.hash = function (base_string, key) {
                return CryptoJS.HmacSHA1(base_string, key).toString(CryptoJS.enc.Base64);
            };
            break;
        case 'PLAINTEXT':
            this.hash = function (base_string, key) {
                return key;
            };
            break;
        case 'RSA-SHA1':
            throw new Error('oauth-1.0a does not support this signature method right now. Coming Soon...');
        default:
            throw new Error('The OAuth 1.0a protocol defines three signature methods: HMAC-SHA1, RSA-SHA1, and PLAINTEXT only');
    }
}

/**
 * OAuth request authorize
 * @param  {Object} request data
 * {
 *     method,
 *     url,
 *     data
 * }
 * @param  {Object} public and secret token
 * @return {Object} OAuth Authorized data
 */
OAuth.prototype.authorize = function (request, token) {
    var oauth_data = {
        oauth_consumer_key: this.consumer.public,
        oauth_nonce: this.getNonce(),
        oauth_signature_method: this.signature_method,
        oauth_timestamp: this.getTimeStamp(),
        oauth_version: this.version
    };

    if (!token) {
        token = {};
    }

    if (token.public) {
        oauth_data.oauth_token = token.public;
    }

    if (!request.data) {
        request.data = {};
    }

    oauth_data.oauth_signature = this.getSignature(request, token.secret, oauth_data);

    return oauth_data;
};

/**
 * Create a OAuth Signature
 * @param  {Object} request data
 * @param  {Object} token_secret public and secret token
 * @param  {Object} oauth_data   OAuth data
 * @return {String} Signature
 */
OAuth.prototype.getSignature = function (request, token_secret, oauth_data) {
    return this.hash(this.getBaseString(request, oauth_data), this.getSigningKey(token_secret));
};

/**
 * Base String = Method + Base Url + ParameterString
 * @param  {Object} request data
 * @param  {Object} OAuth data
 * @return {String} Base String
 */
OAuth.prototype.getBaseString = function (request, oauth_data) {
    return request.method.toUpperCase() + '&' + this.percentEncode(this.getBaseUrl(request.url)) + '&' + this.percentEncode(this.getParameterString(request, oauth_data));
};

/**
 * Get data from url
 * -> merge with oauth data
 * -> percent encode key & value
 * -> sort
 * 
 * @param  {Object} request data
 * @param  {Object} OAuth data
 * @return {Object} Parameter string data
 */
OAuth.prototype.getParameterString = function (request, oauth_data) {
    var base_string_data = this.sortObject(this.percentEncodeData(this.mergeObject(oauth_data, this.mergeObject(request.data, this.deParamUrl(request.url)))));

    var data_str = '';

    //base_string_data to string
    for (var key in base_string_data) {
        data_str += key + '=' + base_string_data[key] + '&';
    }

    //remove the last character
    data_str = data_str.substr(0, data_str.length - 1);
    return data_str;
};

/**
 * Create a Signing Key
 * @param  {String} token_secret Secret Token
 * @return {String} Signing Key
 */
OAuth.prototype.getSigningKey = function (token_secret) {
    token_secret = token_secret || '';

    if (!this.last_ampersand && !token_secret) {
        return this.percentEncode(this.consumer.secret);
    }

    return this.percentEncode(this.consumer.secret) + '&' + this.percentEncode(token_secret);
};

/**
 * Get base url
 * @param  {String} url
 * @return {String}
 */
OAuth.prototype.getBaseUrl = function (url) {
    return url.split('?')[0];
};

/**
 * Get data from String
 * @param  {String} string
 * @return {Object}
 */
OAuth.prototype.deParam = function (string) {
    var arr = decodeURIComponent(string).split('&');
    var data = {};

    for (var i = 0; i < arr.length; i++) {
        var item = arr[i].split('=');
        data[item[0]] = item[1];
    }
    return data;
};

/**
 * Get data from url
 * @param  {String} url
 * @return {Object}
 */
OAuth.prototype.deParamUrl = function (url) {
    var tmp = url.split('?');

    if (tmp.length === 1)
        return {};

    return this.deParam(tmp[1]);
};

/**
 * Percent Encode
 * @param  {String} str
 * @return {String} percent encoded string
 */
OAuth.prototype.percentEncode = function (str) {
    return encodeURIComponent(str)
        .replace(/\!/g, "%21")
        .replace(/\*/g, "%2A")
        .replace(/\'/g, "%27")
        .replace(/\(/g, "%28")
        .replace(/\)/g, "%29");
};

/**
 * Percent Encode Object
 * @param  {Object} data
 * @return {Object} percent encoded data
 */
OAuth.prototype.percentEncodeData = function (data) {
    var result = {};

    for (var key in data) {
        result[this.percentEncode(key)] = this.percentEncode(data[key]);
    }

    return result;
};

/**
 * Get OAuth data as Header
 * @param  {Object} oauth_data
 * @return {String} Header data key - value
 */
OAuth.prototype.toHeader = function (oauth_data) {
    oauth_data = this.sortObject(oauth_data);

    var header_value = 'OAuth ';

    for (var key in oauth_data) {
        if (key.indexOf('oauth_') === -1)
            continue;
        header_value += this.percentEncode(key) + '="' + this.percentEncode(oauth_data[key]) + '"' + this.parameter_seperator;
    }

    return {
        Authorization: header_value.substr(0, header_value.length - this.parameter_seperator.length) //cut the last chars
    };
};

/**
 * Create a random word characters string with input length
 * @return {String} a random word characters string
 */
OAuth.prototype.getNonce = function () {
    var word_characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var result = '';

    for (var i = 0; i < this.nonce_length; i++) {
        result += word_characters[parseInt(Math.random() * word_characters.length, 10)];
    }

    return result;
};

/**
 * Get Current Unix TimeStamp
 * @return {Int} current unix timestamp
 */
OAuth.prototype.getTimeStamp = function () {
    return parseInt(new Date().getTime() / 1000, 10);
};

////////////////////// HELPER FUNCTIONS //////////////////////

/**
 * Merge object
 * @param  {Object} obj1
 * @param  {Object} obj2
 * @return {Object}
 */
OAuth.prototype.mergeObject = function (obj1, obj2) {
    var merged_obj = obj1;
    for (var key in obj2) {
        merged_obj[key] = obj2[key];
    }
    return merged_obj;
};

/**
 * Sort object by key
 * @param  {Object} data
 * @return {Object} sorted object
 */
OAuth.prototype.sortObject = function (data) {
    var keys = Object.keys(data);
    var result = {};

    keys.sort();

    for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        result[key] = data[key];
    }

    return result;
};

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS = CryptoJS || function (g, l) {
    var e = {}, d = e.lib = {}, m = function () { }, k = d.Base = { extend: function (a) { m.prototype = this; var c = new m; a && c.mixIn(a); c.hasOwnProperty("init") || (c.init = function () { c.$super.init.apply(this, arguments) }); c.init.prototype = c; c.$super = this; return c }, create: function () { var a = this.extend(); a.init.apply(a, arguments); return a }, init: function () { }, mixIn: function (a) { for (var c in a) a.hasOwnProperty(c) && (this[c] = a[c]); a.hasOwnProperty("toString") && (this.toString = a.toString) }, clone: function () { return this.init.prototype.extend(this) } },
    p = d.WordArray = k.extend({
        init: function (a, c) { a = this.words = a || []; this.sigBytes = c != l ? c : 4 * a.length }, toString: function (a) { return (a || n).stringify(this) }, concat: function (a) { var c = this.words, q = a.words, f = this.sigBytes; a = a.sigBytes; this.clamp(); if (f % 4) for (var b = 0; b < a; b++) c[f + b >>> 2] |= (q[b >>> 2] >>> 24 - 8 * (b % 4) & 255) << 24 - 8 * ((f + b) % 4); else if (65535 < q.length) for (b = 0; b < a; b += 4) c[f + b >>> 2] = q[b >>> 2]; else c.push.apply(c, q); this.sigBytes += a; return this }, clamp: function () {
            var a = this.words, c = this.sigBytes; a[c >>> 2] &= 4294967295 <<
            32 - 8 * (c % 4); a.length = g.ceil(c / 4)
        }, clone: function () { var a = k.clone.call(this); a.words = this.words.slice(0); return a }, random: function (a) { for (var c = [], b = 0; b < a; b += 4) c.push(4294967296 * g.random() | 0); return new p.init(c, a) }
    }), b = e.enc = {}, n = b.Hex = {
        stringify: function (a) { var c = a.words; a = a.sigBytes; for (var b = [], f = 0; f < a; f++) { var d = c[f >>> 2] >>> 24 - 8 * (f % 4) & 255; b.push((d >>> 4).toString(16)); b.push((d & 15).toString(16)) } return b.join("") }, parse: function (a) {
            for (var c = a.length, b = [], f = 0; f < c; f += 2) b[f >>> 3] |= parseInt(a.substr(f,
            2), 16) << 24 - 4 * (f % 8); return new p.init(b, c / 2)
        }
    }, j = b.Latin1 = { stringify: function (a) { var c = a.words; a = a.sigBytes; for (var b = [], f = 0; f < a; f++) b.push(String.fromCharCode(c[f >>> 2] >>> 24 - 8 * (f % 4) & 255)); return b.join("") }, parse: function (a) { for (var c = a.length, b = [], f = 0; f < c; f++) b[f >>> 2] |= (a.charCodeAt(f) & 255) << 24 - 8 * (f % 4); return new p.init(b, c) } }, h = b.Utf8 = { stringify: function (a) { try { return decodeURIComponent(escape(j.stringify(a))) } catch (c) { throw Error("Malformed UTF-8 data"); } }, parse: function (a) { return j.parse(unescape(encodeURIComponent(a))) } },
    r = d.BufferedBlockAlgorithm = k.extend({
        reset: function () { this._data = new p.init; this._nDataBytes = 0 }, _append: function (a) { "string" == typeof a && (a = h.parse(a)); this._data.concat(a); this._nDataBytes += a.sigBytes }, _process: function (a) { var c = this._data, b = c.words, f = c.sigBytes, d = this.blockSize, e = f / (4 * d), e = a ? g.ceil(e) : g.max((e | 0) - this._minBufferSize, 0); a = e * d; f = g.min(4 * a, f); if (a) { for (var k = 0; k < a; k += d) this._doProcessBlock(b, k); k = b.splice(0, a); c.sigBytes -= f } return new p.init(k, f) }, clone: function () {
            var a = k.clone.call(this);
            a._data = this._data.clone(); return a
        }, _minBufferSize: 0
    }); d.Hasher = r.extend({
        cfg: k.extend(), init: function (a) { this.cfg = this.cfg.extend(a); this.reset() }, reset: function () { r.reset.call(this); this._doReset() }, update: function (a) { this._append(a); this._process(); return this }, finalize: function (a) { a && this._append(a); return this._doFinalize() }, blockSize: 16, _createHelper: function (a) { return function (b, d) { return (new a.init(d)).finalize(b) } }, _createHmacHelper: function (a) {
            return function (b, d) {
                return (new s.HMAC.init(a,
                d)).finalize(b)
            }
        }
    }); var s = e.algo = {}; return e
}(Math);
(function () {
    var g = CryptoJS, l = g.lib, e = l.WordArray, d = l.Hasher, m = [], l = g.algo.SHA1 = d.extend({
        _doReset: function () { this._hash = new e.init([1732584193, 4023233417, 2562383102, 271733878, 3285377520]) }, _doProcessBlock: function (d, e) {
            for (var b = this._hash.words, n = b[0], j = b[1], h = b[2], g = b[3], l = b[4], a = 0; 80 > a; a++) {
                if (16 > a) m[a] = d[e + a] | 0; else { var c = m[a - 3] ^ m[a - 8] ^ m[a - 14] ^ m[a - 16]; m[a] = c << 1 | c >>> 31 } c = (n << 5 | n >>> 27) + l + m[a]; c = 20 > a ? c + ((j & h | ~j & g) + 1518500249) : 40 > a ? c + ((j ^ h ^ g) + 1859775393) : 60 > a ? c + ((j & h | j & g | h & g) - 1894007588) : c + ((j ^ h ^
                g) - 899497514); l = g; g = h; h = j << 30 | j >>> 2; j = n; n = c
            } b[0] = b[0] + n | 0; b[1] = b[1] + j | 0; b[2] = b[2] + h | 0; b[3] = b[3] + g | 0; b[4] = b[4] + l | 0
        }, _doFinalize: function () { var d = this._data, e = d.words, b = 8 * this._nDataBytes, g = 8 * d.sigBytes; e[g >>> 5] |= 128 << 24 - g % 32; e[(g + 64 >>> 9 << 4) + 14] = Math.floor(b / 4294967296); e[(g + 64 >>> 9 << 4) + 15] = b; d.sigBytes = 4 * e.length; this._process(); return this._hash }, clone: function () { var e = d.clone.call(this); e._hash = this._hash.clone(); return e }
    }); g.SHA1 = d._createHelper(l); g.HmacSHA1 = d._createHmacHelper(l)
})();
(function () {
    var g = CryptoJS, l = g.enc.Utf8; g.algo.HMAC = g.lib.Base.extend({
        init: function (e, d) { e = this._hasher = new e.init; "string" == typeof d && (d = l.parse(d)); var g = e.blockSize, k = 4 * g; d.sigBytes > k && (d = e.finalize(d)); d.clamp(); for (var p = this._oKey = d.clone(), b = this._iKey = d.clone(), n = p.words, j = b.words, h = 0; h < g; h++) n[h] ^= 1549556828, j[h] ^= 909522486; p.sigBytes = b.sigBytes = k; this.reset() }, reset: function () { var e = this._hasher; e.reset(); e.update(this._iKey) }, update: function (e) { this._hasher.update(e); return this }, finalize: function (e) {
            var d =
            this._hasher; e = d.finalize(e); d.reset(); return d.finalize(this._oKey.clone().concat(e))
        }
    })
})();

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function () {
    var h = CryptoJS, j = h.lib.WordArray; h.enc.Base64 = {
        stringify: function (b) { var e = b.words, f = b.sigBytes, c = this._map; b.clamp(); b = []; for (var a = 0; a < f; a += 3) for (var d = (e[a >>> 2] >>> 24 - 8 * (a % 4) & 255) << 16 | (e[a + 1 >>> 2] >>> 24 - 8 * ((a + 1) % 4) & 255) << 8 | e[a + 2 >>> 2] >>> 24 - 8 * ((a + 2) % 4) & 255, g = 0; 4 > g && a + 0.75 * g < f; g++) b.push(c.charAt(d >>> 6 * (3 - g) & 63)); if (e = c.charAt(64)) for (; b.length % 4;) b.push(e); return b.join("") }, parse: function (b) {
            var e = b.length, f = this._map, c = f.charAt(64); c && (c = b.indexOf(c), -1 != c && (e = c)); for (var c = [], a = 0, d = 0; d <
            e; d++) if (d % 4) { var g = f.indexOf(b.charAt(d - 1)) << 2 * (d % 4), h = f.indexOf(b.charAt(d)) >>> 6 - 2 * (d % 4); c[a >>> 2] |= (g | h) << 24 - 8 * (a % 4); a++ } return j.create(c, a)
        }, _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    }
})();


//     (c) 2012 Airbnb, Inc.
//     
//     infinity.js may be freely distributed under the terms of the BSD
//     license. For all licensing information, details, and documention:
//     http://airbnb.github.com/infinity
!function (e, t, n) { "use strict"; function l(e, t) { t = t || {}, this.$el = k(), this.$shadow = k(), e.append(this.$el), this.lazy = !!t.lazy, this.lazyFn = t.lazy || null, c(this), this.top = this.$el.offset().top, this.width = 0, this.height = 0, this.pages = [], this.startIndex = 0, E.attach(this) } function c(e) { e._$buffer = k().prependTo(e.$el) } function h(e) { var t, n = e.pages, r = e._$buffer; n.length > 0 ? (t = n[e.startIndex], r.height(t.top)) : r.height(0) } function p(e, t) { t.$el.remove(), e.$el.append(t.$el), C(t, e.height), t.$el.remove() } function d(e) { var n, r, i, s = e.pages, o = !1, u = !0; n = e.startIndex, r = t.min(n + f, s.length); for (n; n < r; n++) i = s[n], e.lazy && i.lazyload(e.lazyFn), o && i.onscreen && (u = !1), u ? i.onscreen || (o = !0, i.appendTo(e.$el)) : (i.stash(e.$shadow), i.appendTo(e.$el)) } function v(e) { var n, i, s, o, u, a = e.startIndex, l = r.scrollTop() - e.top, c = r.height(), p = l + c, v = b(e, l, p); if (v < 0 || v === a) return a; s = e.pages, a = e.startIndex, o = t.min(a + f, s.length), u = t.min(v + f, s.length); for (n = a, i = o; n < i; n++) (n < v || n >= u) && s[n].stash(e.$shadow); return e.startIndex = v, d(e), h(e), v } function m(e, t) { var r; return t instanceof N ? t : (typeof t == "string" && (t = n(t)), r = new N(t), p(e, r), r) } function g(e, t) { y(e) } function y(e) { var t, n, r, i, s, o, u, a, f, l = e.pages, c = []; n = new S(e), c.push(n); for (r = 0, i = l.length; r < i; r++) { t = l[r], u = t.items; for (s = 0, o = u.length; s < o; s++) a = u[s], f = a.clone(), n.hasVacancy() ? n.append(f) : (n = new S(e), c.push(n), n.append(f)); t.remove() } e.pages = c, d(e) } function b(e, n, r) { var i = w(e, n, r); return i = t.max(i - a, 0), i = t.min(i, e.pages.length), i } function w(e, n, r) { var i, s, o, u, f, l, c, h = e.pages, p = n + (r - n) / 2; u = t.min(e.startIndex + a, h.length - 1); if (h.length <= 0) return -1; o = h[u], f = o.top + o.height / 2, c = p - f; if (c < 0) { for (i = u - 1; i >= 0; i--) { o = h[i], f = o.top + o.height / 2, l = p - f; if (l > 0) return l < -c ? i : i + 1; c = l } return 0 } if (c > 0) { for (i = u + 1, s = h.length; i < s; i++) { o = h[i], f = o.top + o.height / 2, l = p - f; if (l < 0) return -l < c ? i : i - 1; c = l } return h.length - 1 } return u } function S(e) { this.parent = e, this.items = [], this.$el = k(), this.id = x.generatePageId(this), this.$el.attr(u, this.id), this.top = 0, this.bottom = 0, this.width = 0, this.height = 0, this.lazyloaded = !1, this.onscreen = !1 } function T(e, t) { var n, r, i, s = t.items; for (n = 0, r = s.length; n < r; n++) if (s[n] === e) { i = n; break } return i == null ? !1 : (s.splice(i, 1), t.bottom -= e.height, t.height = t.bottom - t.top, t.hasVacancy() && g(t.parent, t), !0) } function N(e) { this.$el = e, this.parent = null, this.top = 0, this.bottom = 0, this.width = 0, this.height = 0 } function C(e, t) { var n = e.$el; e.top = t, e.height = n.outerHeight(!0), e.bottom = e.top + e.height, e.width = n.width() } function k() { return n("<div>").css({ margin: 0, padding: 0, border: "none" }) } function L(e) { var t; e ? (t = e.ListView, n.fn.listView = function (e) { return new t(this, e) }) : delete n.fn.listView } var r = n(e), i = e.infinity, s = e.infinity = {}, o = s.config = {}, u = "data-infinity-pageid", a = 1, f = a * 2 + 1; o.PAGE_TO_SCREEN_RATIO = 3, o.SCROLL_THROTTLE = 350, l.prototype.append = function (e) { if (!e || !e.length) return null; var t, n = m(this, e), r = this.pages; this.height += n.height, this.$el.height(this.height), t = r[r.length - 1]; if (!t || !t.hasVacancy()) t = new S(this), r.push(t); return t.append(n), d(this), n }, l.prototype.remove = function () { this.$el.remove(), this.cleanup() }, l.prototype.find = function (e) { var t, r, i; return typeof e == "string" ? (r = this.$el.find(e), i = this.$shadow.find(e), this.find(r).concat(this.find(i))) : e instanceof N ? [e] : (t = [], e.each(function () { var e, r, i, s, o, a, f = n(this).parentsUntil("[" + u + "]").andSelf().first(), l = f.parent(); e = l.attr(u), r = x.lookup(e); if (r) { i = r.items; for (s = 0, o = i.length; s < o; s++) { a = i[s]; if (a.$el.is(f)) { t.push(a); break } } } }), t) }, l.prototype.cleanup = function () { var e = this.pages, t; E.detach(this); while (t = e.pop()) t.cleanup() }; var E = function () { function s() { t || (setTimeout(u, o.SCROLL_THROTTLE), t = !0) } function u() { var e, n; for (e = 0, n = i.length; e < n; e++) v(i[e]); t = !1 } function a() { n && clearTimeout(n), n = setTimeout(f, 200) } function f() { var e, t; for (e = 0; t = i[e]; e++) y(t) } var e = !1, t = !1, n = null, i = []; return { attach: function (t) { e || (r.on("scroll", s), r.on("resize", a), e = !0), i.push(t) }, detach: function (t) { var n, o; for (n = 0, o = i.length; n < o; n++) if (i[n] === t) return i.splice(n, 1), i.length === 0 && (r.off("scroll", s), r.off("resize", a), e = !1), !0; return !1 } } }(); S.prototype.append = function (e) { var t = this.items; t.length === 0 && (this.top = e.top), this.bottom = e.bottom, this.width = this.width > e.width ? this.width : e.width, this.height = this.bottom - this.top, t.push(e), e.parent = this, this.$el.append(e.$el), this.lazyloaded = !1 }, S.prototype.prepend = function (e) { var t = this.items; this.bottom += e.height, this.width = this.width > e.width ? this.width : e.width, this.height = this.bottom - this.top, t.push(e), e.parent = this, this.$el.prepend(e.$el), this.lazyloaded = !1 }, S.prototype.hasVacancy = function () { return this.height < r.height() * o.PAGE_TO_SCREEN_RATIO }, S.prototype.appendTo = function (e) { this.onscreen || (this.$el.appendTo(e), this.onscreen = !0) }, S.prototype.prependTo = function (e) { this.onscreen || (this.$el.prependTo(e), this.onscreen = !0) }, S.prototype.stash = function (e) { this.onscreen && (this.$el.appendTo(e), this.onscreen = !1) }, S.prototype.remove = function () { this.onscreen && (this.$el.remove(), this.onscreen = !1), this.cleanup() }, S.prototype.cleanup = function () { var e = this.items, t; this.parent = null, x.remove(this); while (t = e.pop()) t.cleanup() }, S.prototype.lazyload = function (e) { var t = this.$el, n, r; if (!this.lazyloaded) { for (n = 0, r = t.length; n < r; n++) e.call(t[n], t[n]); this.lazyloaded = !0 } }; var x = function () { var e = []; return { generatePageId: function (t) { return e.push(t) - 1 }, lookup: function (t) { return e[t] || null }, remove: function (t) { var n = t.id; return e[n] ? (e[n] = null, !0) : !1 } } }(); N.prototype.clone = function () { var e = new N(this.$el); return e.top = this.top, e.bottom = this.bottom, e.width = this.width, e.height = this.height, e }, N.prototype.remove = function () { this.$el.remove(), T(this, this.parent), this.cleanup() }, N.prototype.cleanup = function () { this.parent = null }, s.ListView = l, s.Page = S, s.ListItem = N, L(s), s.noConflict = function () { return e.infinity = i, L(i), s } }(window, Math, jQuery);
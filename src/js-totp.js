// https://github.com/heydtn/js-totp/blob/master/totp.js
/* Copyright (C) 2018 by Nathaniel Heydt
 * Copyright (C) 2011 by Mark Percival <m@mdp.im>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/

const jsTOTP = function(time_interval=30) {
  // Credit to github:mdp/rotp Ruby One Time Password Library
  // This is a translation of the just the basic functionality of TOTP from ROTP
  // into minimal javascript

  // https://github.com/mdp/rotp/blob/ecd702e7e8efcb36743b75bfd408c7854ed7e4f4/lib/rotp/base32.rb#L7
  function decode_base32(str) {
      var output = [];
      var matches = str.match(/.{1,8}/g);
      for (block of matches) {
          var char_array = [];
          var decoded = decode_block_base32(block);
          for (c of decoded) {
              char_array.push(String.fromCharCode(c));
          }
          output.push(char_array);
      }
      return flatten(output).join('');
  }

  // https://github.com/mdp/rotp/blob/ecd702e7e8efcb36743b75bfd408c7854ed7e4f4/lib/rotp/base32.rb#L27
  var chars = "abcdefghijklmnopqrstuvwxyz234567";
  function decode_block_base32(block) {
      var length = block.match(/[^=]/g).length;
      var quints = [];
      for (v of block) {
          quints.push(chars.search(v));
      }
      var bytes = [];
      bytes[0] = (quints[0] << 3) + (quints[1] ? quints[1] >> 2 : 0);
      if (length < 3) {
          return bytes;
      }
      bytes[1] = ((quints[1] & 3) << 6) + (quints[2] << 1) + (quints[3] ? quints[3] >> 4 : 0);
      if (length < 4) {
          return bytes;
      }
      bytes[2] = ((quints[3] & 15) << 4) + (quints[4] ? quints[4] >> 1 : 0);
      if (length < 6) {
          return bytes;
      }
      bytes[3] = ((quints[4] & 1) << 7) + (quints[5] << 2) + (quints[6] ? quints[6] >> 3 : 0);
      if (length < 7) {
          return bytes;
      }
      bytes[4] = ((quints[6] & 7) << 5) + (quints[7] || 0);
      return bytes;
  }

  function flatten(arr) {
      var result = [];
      if (!Array.isArray(arr)) {
          return arr;
      }
      for (v of arr) {
          result = result.concat(flatten(v));
      }
      return result;
  }

  // https://github.com/mdp/rotp/blob/ecd702e7e8efcb36743b75bfd408c7854ed7e4f4/lib/rotp/otp.rb#L60
  function int_to_bytestring(int, padding = 8) {
      var result = [];
      while (int != 0) {
          result.push(String.fromCharCode(int & 0xFF));
          int = Number.parseInt(("0".repeat(8) + (int).toString(2).slice(0,-8)), 2);
      }
      return result.reverse().join('').padStart(padding, "\0");
  }

  // https://github.com/mdp/rotp/blob/ecd702e7e8efcb36743b75bfd408c7854ed7e4f4/lib/rotp/otp.rb#L24
  function generate_otp(input, secret, padded=true) {
    secret = secret.toLowerCase();
    var digits = 6;
    hmac = Buffer.from(
        b64_hmac_sha1(decode_base32(secret),int_to_bytestring(input)),
        'base64'
    ).toString('binary')

    offset = hmac.substr(-1).charCodeAt(0) & 0xf;
    code = (hmac.substr(offset).charCodeAt(0) & 0x7f) << 24 | (hmac.substr(offset + 1).charCodeAt(0) & 0xff) << 16 | (hmac.substr(offset + 2).charCodeAt(0) & 0xff) << 8 | (hmac.substr(offset + 3).charCodeAt(0) & 0xff);
    if (padded) {
      return (code % 10 ** digits).toString().padStart(digits, '0');
    } else {
      return (code % 10 ** digits).toString();
    }
  }

  // https://github.com/mdp/rotp/blob/ecd702e7e8efcb36743b75bfd408c7854ed7e4f4/lib/rotp/totp.rb#L28
  function otp_now(secret, padded=true) {
    return generate_otp(Math.floor(Math.floor(Date.now() / 1000) / time_interval), secret, padded);
  }

  // This is required to calculate base64 HMAC_SHA1 for TOTP
  // http://pajhome.org.uk/crypt/md5/sha1.js
  // this version only including what's necessary for base64 HMAC_SHA1

  /*
   * Copyright (c) 1998 - 2009, Paul Johnston & Contributors
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
   *
   * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   *
   * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  */

  b64_hmac_sha1 = (function() {
      var b64pad = "="; /* base-64 pad character. "=" for strict RFC compliance   */
      var chrsz = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

      function binb2b64(binarray)
      {
        var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var str = "";
        for(var i = 0; i < binarray.length * 4; i += 3)
        {
          var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                      | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                      |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
          for(var j = 0; j < 4; j++)
          {
            if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
          }
        }
        return str;
      }

      function binb2b64(binarray)
      {
        var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var str = "";
        for(var i = 0; i < binarray.length * 4; i += 3)
        {
          var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                      | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                      |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
          for(var j = 0; j < 4; j++)
          {
            if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
          }
        }
        return str;
      }

      function core_hmac_sha1(key, data)
      {
        var bkey = str2binb(key);
        if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

        var ipad = Array(16), opad = Array(16);
        for(var i = 0; i < 16; i++)
        {
          ipad[i] = bkey[i] ^ 0x36363636;
          opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
        return core_sha1(opad.concat(hash), 512 + 160);
      }

      function str2binb(str)
      {
        var bin = Array();
        var mask = (1 << chrsz) - 1;
        for(var i = 0; i < str.length * chrsz; i += chrsz)
          bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
        return bin;
      }

      function core_sha1(x, len)
      {
        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        var w = Array(80);
        var a =  1732584193;
        var b = -271733879;
        var c = -1732584194;
        var d =  271733878;
        var e = -1009589776;

        for(var i = 0; i < x.length; i += 16)
        {
          var olda = a;
          var oldb = b;
          var oldc = c;
          var oldd = d;
          var olde = e;

          for(var j = 0; j < 80; j++)
          {
            if(j < 16) w[j] = x[i + j];
            else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
            var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                             safe_add(safe_add(e, w[j]), sha1_kt(j)));
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
          }

          a = safe_add(a, olda);
          b = safe_add(b, oldb);
          c = safe_add(c, oldc);
          d = safe_add(d, oldd);
          e = safe_add(e, olde);
        }
        return Array(a, b, c, d, e);

      }

      function safe_add(x, y)
      {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
      }

      function sha1_ft(t, b, c, d)
      {
        if(t < 20) return (b & c) | ((~b) & d);
        if(t < 40) return b ^ c ^ d;
        if(t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
      }

      function sha1_kt(t)
      {
        return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
               (t < 60) ? -1894007588 : -899497514;
      }

      function rol(num, cnt)
      {
        return (num << cnt) | (num >>> (32 - cnt));
      }

      return function(key, data){ return binb2b64(core_hmac_sha1(key, data));};

  })();

  //
  // End of content from http://pajhome.org.uk/crypt/md5/sha1.js
  //

  this.otp_now      = otp_now;
  this.generate_otp = generate_otp;
}

module.exports = jsTOTP;

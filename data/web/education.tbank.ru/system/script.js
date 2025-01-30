var __assign =
  (this && this.__assign) ||
  function() {
    __assign =
      Object.assign ||
      function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
          s = arguments[i];
          for (var p in s)
            if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
      };
    return __assign.apply(this, arguments);
  };

function getCookie(name) {
  var matches = document.cookie.match(
    new RegExp(
      "(?:^|; )" +
        name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, "\\$1") +
        "=([^;]*)"
    )
  );
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

function setCookie(name, value, options) {
  if (options === void 0) {
    options = {};
  }
  options = __assign({}, options);
  if (options.expires instanceof Date) {
    options.expires = options.expires.toUTCString();
  }
  var updatedCookie =
    encodeURIComponent(name) + "=" + encodeURIComponent(value);
  for (var optionKey in options) {
    updatedCookie += "; " + optionKey;
    var optionValue = options[optionKey];
    if (optionValue !== true) {
      updatedCookie += "=" + optionValue;
    }
  }

  document.cookie = updatedCookie;
}

function deleteCookie(name, options) {
  if (options === void 0) {
    options = {};
  }
  setCookie(name, "", __assign({ "max-age": -1 }, options));
}

function getAllCookies() {
  return document.cookie.split(";").map(function(cookie) {
    return cookie.trim();
  });
}

function getCookiesSizes() {
  return getAllCookies().reduce(function(result, cookie) {
    var parsedCookie = cookie.split("=");
    var key = decodeURIComponent(parsedCookie[0] || "");
    var value = decodeURIComponent(parsedCookie[1] || "");
    if (key && value) {
      result[key] = value.length;
    }
    return result;
  }, {});
}

function getQuery(name) {
  var url = new URL(location);
  return url.searchParams.get(name);
}

function setQuery(name, value) {
  var url = new URL(location);
  url.searchParams.set(name, value);
  history.pushState(null, "", url);
}

var pageErrorCode = document.querySelector(".picture").alt;
var sessionid = getCookie("psid");
var wuid = getCookie("__P__wuid");
var requestUrl =
  "/api/front/log/collect?origin=web,ib5,platform&component=maintenance&level=error&event=SYSTEM_ERROR_PAGE&message=code=" +
  pageErrorCode +
  (pageErrorCode === "431" ? "&cookies=" + JSON.stringify(getCookiesSizes()) : "") +
  (sessionid ? "&sessionid=" + sessionid : "") +
  (wuid ? "&wuid=" + wuid : "") +
  (document.referrer ? "&referrer=" + document.referrer : "");

new Image().src = requestUrl;

function clearFatCookies() {
  var cookies = getAllCookies().sort(function(a, b) {
    return b.length - a.length;
  });
  var limit = 0;
  if (cookies.length === 0) {
    return;
  }
  ["s_sq", "_P_handsetDetection"].forEach(function(cookie) {
    deleteCookie(cookie, { domain: ".tinkoff.ru", path: "/" });
  });
  for (var i = 0; i < cookies.length; i++) {
    var parsedCookie = cookies[i].split("=");
    var key = decodeURIComponent(parsedCookie[0] || "");
    var value = decodeURIComponent(parsedCookie[1] || "");
    if (key && value) {
      deleteCookie(key, { domain: ".tinkoff.ru", path: "/" });
      var success = !getCookie(key);
      if (success) {
        limit++;
      }
      if (limit === 4) {
        break;
      }
    }
  }
}

function reload() {
  setTimeout(function() {
    setQuery("clearCookies", "false");
    location.reload();
  }, 1000);
}

if (pageErrorCode === "431" && getQuery("clearCookies") !== "false") {
  clearFatCookies();
  reload();
}

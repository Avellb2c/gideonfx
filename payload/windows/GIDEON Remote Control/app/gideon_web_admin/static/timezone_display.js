/* GIDEON: render server timestamps in the operator's Peru timezone.
 *
 * The API and database intentionally keep UTC/offset-aware values for
 * ordering, signatures and audit. This display-only layer converts ISO
 * timestamps in visible text nodes so every page (including partial updates)
 * uses the same local clock without changing the stored value.
 */
(function () {
  "use strict";

  var PERU_TIME_ZONE = "America/Lima";
  var ISO_TIMESTAMP = /\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\b/g;
  var formatter = new Intl.DateTimeFormat("es-PE", {
    timeZone: PERU_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    hourCycle: "h23"
  });

  function localTimestamp(value) {
    var date = new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    var parts = formatter.formatToParts(date).reduce(function (result, part) {
      result[part.type] = part.value;
      return result;
    }, {});
    if (!parts.year || !parts.month || !parts.day || !parts.hour) return null;
    return parts.day + "/" + parts.month + "/" + parts.year + " " +
      parts.hour + ":" + (parts.minute || "00") + ":" + (parts.second || "00");
  }

  function shouldSkip(node) {
    var parent = node.parentElement;
    if (!parent) return true;
    var tag = parent.tagName;
    return tag === "SCRIPT" || tag === "STYLE" || tag === "NOSCRIPT" ||
      tag === "INPUT" || tag === "TEXTAREA" || tag === "OPTION";
  }

  function convertTextNode(node) {
    if (!node || shouldSkip(node)) return;
    var source = node.nodeValue || "";
    if (!ISO_TIMESTAMP.test(source)) {
      ISO_TIMESTAMP.lastIndex = 0;
      return;
    }
    ISO_TIMESTAMP.lastIndex = 0;
    var converted = source.replace(ISO_TIMESTAMP, function (raw) {
      return localTimestamp(raw) || raw;
    });
    ISO_TIMESTAMP.lastIndex = 0;
    if (converted === source) return;
    var parent = node.parentElement;
    if (parent && !parent.getAttribute("title")) {
      parent.setAttribute("title", "Hora de Perú · UTC original: " + source.trim());
    }
    node.nodeValue = converted;
  }

  function convert(root) {
    if (!root) return;
    if (root.nodeType === Node.TEXT_NODE) {
      convertTextNode(root);
      return;
    }
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    var node;
    while ((node = walker.nextNode())) convertTextNode(node);
  }

  function start() {
    convert(document.body);
    var observer = new MutationObserver(function (mutations) {
      mutations.forEach(function (mutation) {
        for (var i = 0; i < mutation.addedNodes.length; i += 1) {
          convert(mutation.addedNodes[i]);
        }
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();

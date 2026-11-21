// Applies the saved theme before first paint (external file: the CSP forbids inline scripts).
(function () {
  try {
    var t = localStorage.getItem("conrad-theme") || "system";
    var dark = t === "dark" || (t === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
    var l = localStorage.getItem("i18nextLng");
    if (l) document.documentElement.lang = l.slice(0, 2);
  } catch (e) {}
})();

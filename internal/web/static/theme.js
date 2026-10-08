// Theme choice (auto / light / dark), remembered per browser. Loaded in
// <head> without defer so the saved theme applies before the page paints.
(function () {
  var KEY = "tunnelward-theme";
  var root = document.documentElement;

  function apply(value) {
    if (value === "light" || value === "dark") {
      root.setAttribute("data-theme", value);
    } else {
      root.removeAttribute("data-theme");
    }
  }

  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  apply(saved);

  document.addEventListener("DOMContentLoaded", function () {
    var select = document.getElementById("theme");
    if (!select) return;
    select.value = saved === "light" || saved === "dark" ? saved : "auto";
    select.closest("label").hidden = false; // only useful with JavaScript
    select.addEventListener("change", function () {
      apply(select.value);
      try { localStorage.setItem(KEY, select.value); } catch (e) {}
    });
  });
})();

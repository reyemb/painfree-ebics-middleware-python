/* The only JavaScript in this console, and the only thing that stops working
   when scripting is off.

   It runs inline in <head>, before any of <body> has been parsed, so the theme
   attribute is on <html> before the first paint: there is no flash of the wrong
   theme on a reload. That is the whole reason it is not a deferred file.

   Three states, and `system` is the absence of a choice rather than a third
   value written down. With no `data-theme` attribute the root keeps
   `color-scheme: light dark` and the browser follows `prefers-color-scheme`,
   which is what makes the default work with scripting disabled too -- the
   toggle changes the theme, it is not what applies it.

   `data-js` is set on <html> here and is what reveals the toggle. A control
   that cannot work is worse than a control that is not offered. */

(function () {
  var root = document.documentElement;
  var KEY = "painfree.theme";

  function read() {
    try {
      var stored = window.localStorage.getItem(KEY);
      return stored === "light" || stored === "dark" ? stored : "system";
    } catch (error) {
      /* Private mode, or storage denied by policy. The console still works;
         the choice just does not survive the reload. */
      return "system";
    }
  }

  function apply(choice) {
    if (choice === "system") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", choice);
    }
  }

  function mark(choice) {
    var buttons = document.querySelectorAll("[data-theme-choice]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute(
        "aria-pressed",
        buttons[i].getAttribute("data-theme-choice") === choice ? "true" : "false");
    }
  }

  var current = read();
  apply(current);
  root.setAttribute("data-js", "on");

  document.addEventListener("click", function (event) {
    var target = event.target;
    var button = target && target.closest
      ? target.closest("[data-theme-choice]") : null;
    if (!button) {
      return;
    }
    current = button.getAttribute("data-theme-choice");
    apply(current);
    try {
      if (current === "system") {
        window.localStorage.removeItem(KEY);
      } else {
        window.localStorage.setItem(KEY, current);
      }
    } catch (error) {
      /* Nothing to do: the theme is applied, it simply will not be remembered. */
    }
    mark(current);
  });

  /* The server renders `system` as the pressed segment, because that is the
     default. If a choice was stored, this is the earliest moment the buttons
     exist to be corrected. */
  document.addEventListener("DOMContentLoaded", function () { mark(current); });
})();

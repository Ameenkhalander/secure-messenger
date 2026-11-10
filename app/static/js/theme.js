// Runs synchronously in <head> to avoid a flash of the wrong theme.
(function () {
  var saved = null;
  try { saved = localStorage.getItem('sealed.theme'); } catch (e) {}
  var theme = saved || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.setAttribute('data-bs-theme', theme);
  window.sealedToggleTheme = function () {
    var next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-bs-theme', next);
    try { localStorage.setItem('sealed.theme', next); } catch (e) {}
  };
  document.addEventListener('click', function (ev) {
    var t = ev.target.closest && ev.target.closest('[data-theme-toggle]');
    if (t) window.sealedToggleTheme();
  });
})();

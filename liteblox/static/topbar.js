/* The top bar: the light/dark toggle (per browser) and the Tools menu.

   Loaded in <head> without defer, so the saved theme is on <html> before the first paint (no flash).
   Auto follows the system; Light and Dark set data-theme, which app.css's dark rules check either way. */
(function () {
  const KEY = 'liteblox-theme';
  const ORDER = ['auto', 'light', 'dark'];
  const LABEL = {auto: 'Theme: Auto (follows the system)', light: 'Theme: Light', dark: 'Theme: Dark'};

  function saved() {
    try {
      const v = localStorage.getItem(KEY);
      return ORDER.indexOf(v) >= 0 ? v : 'auto';
    } catch (e) {
      return 'auto';                       // storage blocked: follow the system
    }
  }

  function apply(choice) {
    const root = document.documentElement;
    if (choice === 'auto') delete root.dataset.theme;
    else root.dataset.theme = choice;
    const button = document.getElementById('theme-toggle');
    if (button) {
      button.dataset.themeChoice = choice;
      button.title = LABEL[choice];
      button.setAttribute('aria-label', LABEL[choice]);
    }
  }

  let current = saved();                   // kept here too, so the toggle still cycles when storage is blocked
  apply(current);
  document.addEventListener('DOMContentLoaded', function () { apply(current); });
  // IPAM's network list: folded to squares or not, per browser like the theme, set before the first paint too
  const TREE = 'liteblox-ipam-tree';

  function treeSaved() {
    try {
      return localStorage.getItem(TREE) === 'collapsed';
    } catch (e) {
      return false;
    }
  }

  function applyTree(collapsed) {
    const root = document.documentElement;
    if (collapsed) root.dataset.ipamTree = 'collapsed';
    else delete root.dataset.ipamTree;
    const label = collapsed ? 'Expand the network list' : 'Collapse the network list';
    document.querySelectorAll('[data-ipam-tree-toggle]').forEach(function (b) {
      b.setAttribute('aria-expanded', String(!collapsed));
      b.title = label;
      b.setAttribute('aria-label', label);
    });
  }

  let treeCollapsed = treeSaved();
  applyTree(treeCollapsed);
  document.addEventListener('DOMContentLoaded', function () { applyTree(treeCollapsed); });

  // a choice made in another tab applies here too
  window.addEventListener('storage', function (e) {
    if (e.key === KEY) { current = saved(); apply(current); }
    if (e.key === TREE) { treeCollapsed = treeSaved(); applyTree(treeCollapsed); }
  });

  function closeMenus(except) {
    document.querySelectorAll('details.nav-menu[open]').forEach(function (d) {
      if (d !== except) d.removeAttribute('open');
    });
  }

  document.addEventListener('click', function (e) {
    const toggle = e.target.closest('#theme-toggle');
    if (toggle) {
      current = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
      try { localStorage.setItem(KEY, current); } catch (err) { /* this page only */ }
      apply(current);
    }
    if (e.target.closest('[data-ipam-tree-toggle]')) {
      treeCollapsed = !treeCollapsed;
      try {
        if (treeCollapsed) localStorage.setItem(TREE, 'collapsed');
        else localStorage.removeItem(TREE);
      } catch (err) { /* this page only */ }
      applyTree(treeCollapsed);
    }
    closeMenus(e.target.closest('details.nav-menu'));
    // a menu entry opens in a new tab: close the menu behind it
    if (e.target.closest('details.nav-menu a')) closeMenus(null);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    const open = document.querySelector('details.nav-menu[open]');
    if (!open) return;
    open.removeAttribute('open');
    open.querySelector('summary').focus();
  });
})();

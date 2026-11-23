/* LiteBlox's confirmation dialog, in place of the browser's confirm().

   A form asks with data-confirm="Delete bob?"; data-confirm-ok names the button ("Delete"),
   {field} in the question is replaced by that select's chosen option (or the field's value),
   data-confirm-unless="field=value" skips the question when the field has that value, and
   data-confirm-when="box" asks only when that checkbox is newly ticked ("!box": newly unticked).
   htmx's hx-confirm goes through the same dialog. Cancel has the focus, so Enter and Esc
   never do the destructive thing. */
(function () {
  const dialog = document.getElementById('confirm-dialog');
  if (!dialog) return;
  const text = dialog.querySelector('.confirm-text');
  const ok = dialog.querySelector('button[value="ok"]');
  let answer = null;

  function ask(question, okLabel) {
    text.textContent = question;
    ok.textContent = okLabel || 'OK';
    dialog.returnValue = '';
    dialog.showModal();
    return new Promise(function (resolve) { answer = resolve; });
  }

  // for scripts that ask outside a form (the subnet calculator): liteblox.confirm(question, okLabel) → Promise<bool>
  window.liteblox = Object.assign(window.liteblox || {}, {confirm: ask});

  dialog.addEventListener('close', function () {
    if (answer) answer(dialog.returnValue === 'ok');
    answer = null;
  });

  function fill(form, question) {
    return question.replace(/\{([\w-]+)\}/g, function (whole, name) {
      const field = form.elements[name];
      if (!field) return whole;
      return field.selectedOptions ? field.selectedOptions[0].text : field.value;
    });
  }

  document.addEventListener('submit', function (e) {
    const form = e.target;
    if (!form.dataset.confirm) return;
    if (form.dataset.confirmed) {            // the second, confirmed submit
      delete form.dataset.confirmed;
      return;
    }
    const unless = (form.dataset.confirmUnless || '').split('=');
    if (unless.length === 2 && form.elements[unless[0]] && form.elements[unless[0]].value === unless[1]) return;
    const when = form.dataset.confirmWhen;
    if (when) {
      const box = form.elements[when.replace(/^!/, '')];
      const want = when[0] !== '!';
      if (!box || box.checked !== want || box.defaultChecked === want) return;
    }
    e.preventDefault();
    const submitter = e.submitter;
    ask(fill(form, form.dataset.confirm), form.dataset.confirmOk).then(function (yes) {
      if (!yes) return;
      form.dataset.confirmed = '1';
      form.requestSubmit(submitter || undefined);
    });
  });

  document.addEventListener('htmx:confirm', function (e) {
    if (!e.detail.question) return;
    e.preventDefault();
    ask(e.detail.question, e.detail.elt.getAttribute('data-confirm-ok')).then(function (yes) {
      if (yes) e.detail.issueRequest(true);
    });
  });
})();

/* "/" jumps to the search box in the top bar (unless you're typing somewhere), and a page with a filter
   box takes ?filter= from its address, so a search result opens its zone or subnet already filtered. */
(function () {
  const box = document.getElementById('search-box');
  document.addEventListener('keydown', function (e) {
    if (!box || e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
    e.preventDefault();
    box.focus();
    box.select();
  });
  const wanted = new URLSearchParams(location.search).get('filter');
  const filter = document.querySelector('#record-filter, #address-filter');
  if (wanted && filter) {
    filter.value = wanted;
    filter.dispatchEvent(new Event('input'));
  }
})();

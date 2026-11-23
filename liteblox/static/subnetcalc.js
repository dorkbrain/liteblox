/* The subnet calculator (Tools → Subnet Calculator).
   An altered version of David C A Croft's Visual Subnet Calculator (https://github.com/davidc/subnets),
   Copyright (c) 2002, 2011, 2018, 2019 David C A Croft, under the license in subnetcalc-LICENSE.txt.
   Reworked for LiteBlox; this is not the original software.
   In the app: questions go through app.js's dialog (never confirm()), messages show on the page (no alert()),
   and Copy Table falls back to execCommand or a text box where the Clipboard API is missing (plain HTTP). */
(function () {
  // =====================
  // State
  // =====================

  var curNetwork = 0;
  var curMask = 0;
  var rootSubnet;
  var showUseable = false; // false = full range, true = useable IPs
  var exclusions = []; // [{addr, mask, start, end}, ...]

  var ICON_PLUS = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/></svg>';
  var ICON_CHECK = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>';

  // =====================
  // Core Logic (preserved from original)
  // =====================

  function inet_ntoa(addrint) {
    return ((addrint >> 24) & 0xff) + '.' +
      ((addrint >> 16) & 0xff) + '.' +
      ((addrint >> 8) & 0xff) + '.' +
      (addrint & 0xff);
  }

  function inet_aton(addrstr) {
    var re = /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/;
    var res = re.exec(addrstr);
    if (res === null) return null;
    for (var i = 1; i <= 4; i++) {
      if (res[i] < 0 || res[i] > 255) return null;
    }
    return ((res[1] << 24) | (res[2] << 16) | (res[3] << 8) | parseInt(res[4])) >>> 0;
  }

  function network_address(ip, mask) {
    for (var i = 31 - mask; i >= 0; i--) {
      ip &= ~(1 << i);
    }
    return ip >>> 0;
  }

  function subnet_addresses(mask) {
    return 2 ** (32 - mask);
  }

  function subnet_last_address(subnet, mask) {
    return subnet + subnet_addresses(mask) - 1;
  }

  function subnet_netmask(mask) {
    return network_address(0xffffffff, mask);
  }

  function nodeToString(node) {
    if (node[2]) {
      return '1' + nodeToString(node[2][0]) + nodeToString(node[2][1]);
    } else {
      return '0';
    }
  }

  function binToAscii(str) {
    var curOut = '';
    var curBit = 0;
    var curChar = 0;
    for (var i = 0; i < str.length; i++) {
      if (str.charAt(i) == '1') {
        curChar |= 1 << curBit;
      }
      curBit++;
      if (curBit > 3) {
        curOut += curChar.toString(16);
        curChar = 0;
        curBit = 0;
      }
    }
    if (curBit > 0) {
      curOut += curChar.toString(16);
    }
    return str.length + '.' + curOut;
  }

  function asciiToBin(str) {
    var re = /([0-9]+)\.([0-9a-f]+)/;
    var res = re.exec(str);
    if (!res) return '0';
    var out = '';
    for (var i = 0; i < res[1]; i++) {
      var ch = parseInt(res[2].charAt(Math.floor(i / 4)), 16);
      var pos = i % 4;
      out += (ch & (1 << pos) ? '1' : '0');
    }
    return out;
  }

  function loadNode(curNode, division) {
    if (division.charAt(0) == '0') {
      return division.substr(1);
    } else {
      curNode[2] = new Array();
      curNode[2][0] = [0, 0, null];
      curNode[2][1] = [0, 0, null];
      division = loadNode(curNode[2][0], division.substr(1));
      division = loadNode(curNode[2][1], division);
      return division;
    }
  }

  function updateNumChildren(node) {
    if (node[2] == null) {
      node[1] = 0;
      return 1;
    } else {
      node[1] = updateNumChildren(node[2][0]) + updateNumChildren(node[2][1]);
      return node[1];
    }
  }

  function updateDepthChildren(node) {
    if (node[2] == null) {
      node[0] = 0;
      return 1;
    } else {
      node[0] = updateDepthChildren(node[2][0]) + updateDepthChildren(node[2][1]);
      return node[1];
    }
  }

  function divide(node) {
    node[2] = new Array();
    node[2][0] = [0, 0, null];
    node[2][1] = [0, 0, null];
    recreateTables();
  }

  function join(node) {
    node[2] = null;
    recreateTables();
  }

  function newJoin(joinnode) {
    return function () { join(joinnode); };
  }

  function parseQueryString(str) {
    str = str ? str : location.search;
    var query = str.charAt(0) == '?' ? str.substring(1) : str;
    var args = {};
    if (query) {
      var fields = query.split('&');
      for (var f = 0; f < fields.length; f++) {
        var field = fields[f].split('=');
        if (field.length < 2) continue;
        args[decodeURIComponent(field[0].replace(/\+/g, ' '))] =
          decodeURIComponent(field[1].replace(/\+/g, ' '));
      }
    }
    return args;
  }

  // =====================
  // Exclusion Logic
  // =====================

  function parseExclusions(text) {
    exclusions = [];
    if (!text || !text.trim()) return;
    var parts = text.split(/[,\n]+/);
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (!p) continue;
      var m = p.match(/^([0-9.]+)\/([0-9]+)$/);
      if (!m) continue;
      var addr = inet_aton(m[1]);
      var mask = parseInt(m[2]);
      if (addr === null || mask < 0 || mask > 32) continue;
      addr = network_address(addr, mask);
      exclusions.push({
        addr: addr,
        mask: mask,
        start: addr,
        end: subnet_last_address(addr, mask)
      });
    }
  }

  function isExcluded(address, mask) {
    var start = address;
    var end = subnet_last_address(address, mask);
    for (var i = 0; i < exclusions.length; i++) {
      if (exclusions[i].start <= start && exclusions[i].end >= end) return true;
    }
    return false;
  }

  function autoApplyExclusion(node, nodeAddr, nodeMask, exAddr, exMask) {
    var nodeEnd = subnet_last_address(nodeAddr, nodeMask);
    var exEnd = subnet_last_address(exAddr, exMask);

    // No overlap
    if (nodeEnd < exAddr || nodeAddr > exEnd) return;

    // Node fully contained by exclusion — leaf will render red, nothing to divide
    if (exAddr <= nodeAddr && exEnd >= nodeEnd) return;

    // Partial overlap — divide if leaf and not too deep
    if (node[2] === null) {
      if (nodeMask >= 30) return; // guard against runaway depth
      node[2] = [[0, 0, null], [0, 0, null]];
    }

    var halfSize = subnet_addresses(nodeMask + 1);
    autoApplyExclusion(node[2][0], nodeAddr, nodeMask + 1, exAddr, exMask);
    autoApplyExclusion(node[2][1], nodeAddr + halfSize, nodeMask + 1, exAddr, exMask);
  }

  function applyAllExclusions() {
    for (var i = 0; i < exclusions.length; i++) {
      var ex = exclusions[i];
      autoApplyExclusion(rootSubnet, curNetwork, curMask, ex.addr, ex.mask);
    }
  }

  // =====================
  // Messages and questions (the app's, in place of alert() and confirm())
  // =====================

  function showMessage(text, kind) {
    var box = document.getElementById('calc-message');
    if (!text) { box.hidden = true; return; }
    box.className = kind === 'error' ? 'error' : 'notice';
    box.textContent = text;
    box.hidden = false;
  }

  function ask(question, okLabel) {
    return window.liteblox && window.liteblox.confirm
      ? window.liteblox.confirm(question, okLabel)
      : Promise.resolve(false);   // without app.js's dialog, keep what's there
  }

  // =====================
  // Copy Table
  // =====================

  function tableText() {
    var rows = document.querySelectorAll('#calcbody tr');
    var tableRows = [['Subnet', 'Netmask', 'Range', 'Hosts']];
    var excluded = [];
    rows.forEach(function (row) {
      var cells = row.querySelectorAll('td');
      if (cells.length < 4) return;
      if (cells[0].classList.contains('cell-subnet-excluded')) {
        excluded.push(cells[0].textContent.trim());
      } else {
        tableRows.push([0, 1, 2, 3].map(function (i) { return cells[i].textContent.trim(); }));
      }
    });

    var widths = [0, 0, 0, 0];
    tableRows.forEach(function (row) {
      row.forEach(function (cell, i) { widths[i] = Math.max(widths[i], cell.length); });
    });

    var lines = tableRows.map(function (row) {
      return row.map(function (cell, i) {
        return i < row.length - 1 ? cell.padEnd(widths[i]) : cell;
      }).join('  ');
    });

    lines.push('');
    lines.push('Supernet:  ' + inet_ntoa(curNetwork) + '/' + curMask);
    if (excluded.length) {
      lines.push('Excluded:  ' + excluded.join(', '));
    }
    return lines.join('\n');
  }

  function flashButton(html) {
    var btn = document.getElementById('copyBtn');
    if (!btn.dataset.label) btn.dataset.label = btn.innerHTML;
    btn.innerHTML = html;
    clearTimeout(btn._restore);
    btn._restore = setTimeout(function () { btn.innerHTML = btn.dataset.label; }, 1500);
  }

  // navigator.clipboard only exists on HTTPS or localhost; over plain HTTP try execCommand, else show the text to copy
  function legacyCopy(text) {
    var area = document.getElementById('copy-fallback');
    area.value = text;
    area.hidden = false;
    area.focus();
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    if (ok) {
      area.hidden = true;
      flashButton(ICON_CHECK + ' Copied!');
    } else {
      flashButton('Select and copy');   // the text box stays, selected
    }
  }

  function copyTable() {
    var text = tableText();
    document.getElementById('copy-fallback').hidden = true;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () {
        flashButton(ICON_CHECK + ' Copied!');
      }, function () { legacyCopy(text); });
    } else {
      legacyCopy(text);
    }
  }

  // =====================
  // UI Functions
  // =====================

  function toggleRangeMode() {
    showUseable = !showUseable;
    document.querySelector('#rangeHeader span').textContent = showUseable ? 'Useable IPs' : 'Range';
    recreateTables();
  }

  function updateNetwork() {
    var form = document.getElementById('calcForm');
    showMessage('');
    parseExclusions(form.elements['exclusions'].value);
    var newNetworkStr = form.elements['network'].value.trim();
    var newMask = parseInt(form.elements['netbits'].value);
    var newNetwork = inet_aton(newNetworkStr);

    if (newNetwork === null) {
      showMessage('Invalid network address entered', 'error');
      return;
    }

    if (isNaN(newMask) || newMask < 0 || newMask > 32) {
      showMessage('The network mask you have entered is invalid', 'error');
      return;
    }

    var tmpNetwork = network_address(newNetwork, newMask);
    if (newNetwork != tmpNetwork) {
      showMessage('The network address entered is not on a network boundary for this mask. It has been changed to ' + inet_ntoa(tmpNetwork) + '.');
      newNetwork = tmpNetwork;
      form.elements['network'].value = inet_ntoa(tmpNetwork);
    }

    function keepMask() {
      form.elements['netbits'].value = curMask;
      curNetwork = newNetwork;
      recreateTables();
    }

    if (curMask == 0) {
      curMask = newMask;
      curNetwork = newNetwork;
      startOver();
    } else if (curMask != newMask) {
      ask('You are changing the base network from /' + curMask + ' to /' + newMask + '. This will reset any changes you have made. Proceed?', 'Change').then(function (yes) {
        if (yes) {
          curMask = newMask;
          curNetwork = newNetwork;
          startOver();
        } else {
          keepMask();
        }
      });
    } else {
      keepMask();
    }
  }

  function startOver() {
    rootSubnet = [0, 0, null];
    recreateTables();
  }

  function recreateTables() {
    var calcbody = document.getElementById('calcbody');
    if (!calcbody) return;

    while (calcbody.hasChildNodes()) {
      calcbody.removeChild(calcbody.firstChild);
    }

    applyAllExclusions();

    updateNumChildren(rootSubnet);
    updateDepthChildren(rootSubnet);

    createRow(calcbody, rootSubnet, curNetwork, curMask, [curMask, rootSubnet[1], rootSubnet], rootSubnet[0]);

    document.getElementById('joinHeader').colSpan = (rootSubnet[0] > 0 ? rootSubnet[0] : 1);

    // Update bookmark link
    var link = document.getElementById('saveLink');
    if (link) {
      var href = '?network=' + inet_ntoa(curNetwork) + '&mask=' + curMask + '&division=' + binToAscii(nodeToString(rootSubnet));
      var exclField = document.getElementById('calcForm').elements['exclusions'];
      if (exclField && exclField.value.trim()) {
        href += '&exclusions=' + encodeURIComponent(exclField.value.trim());
      }
      link.href = href;
    }
  }

  function createRow(calcbody, node, address, mask, labels, depth) {
    if (node[2]) {
      var newlabels = labels.slice();
      newlabels.push(mask + 1);
      newlabels.push(node[2][0][1]);
      newlabels.push(node[2][0]);
      createRow(calcbody, node[2][0], address, mask + 1, newlabels, depth - 1);

      newlabels = [];
      newlabels.push(mask + 1);
      newlabels.push(node[2][1][1]);
      newlabels.push(node[2][1]);
      createRow(calcbody, node[2][1], address + subnet_addresses(mask + 1), mask + 1, newlabels, depth - 1);
    } else {
      var newRow = document.createElement('TR');
      calcbody.appendChild(newRow);

      // Subnet address
      var cell = document.createElement('TD');
      cell.className = 'cell-mono ' + (isExcluded(address, mask) ? 'cell-subnet-excluded' : 'cell-subnet');
      cell.textContent = inet_ntoa(address) + '/' + mask;
      newRow.appendChild(cell);

      // Netmask
      cell = document.createElement('TD');
      cell.className = 'cell-mono';
      cell.textContent = inet_ntoa(subnet_netmask(mask));
      newRow.appendChild(cell);

      var addressFirst = address;
      var addressLast = subnet_last_address(address, mask);
      var useableFirst = address + 1;
      var useableLast = addressLast - 1;
      var numHosts, rangeText;

      if (mask == 32) {
        rangeText = inet_ntoa(addressFirst);
        numHosts = 1;
      } else if (mask == 31) {
        rangeText = inet_ntoa(addressFirst) + ' – ' + inet_ntoa(addressLast);
        numHosts = 2;
      } else {
        if (showUseable) {
          rangeText = inet_ntoa(useableFirst) + ' – ' + inet_ntoa(useableLast);
        } else {
          rangeText = inet_ntoa(addressFirst) + ' – ' + inet_ntoa(addressLast);
        }
        numHosts = (1 + useableLast - useableFirst);
      }

      // Range / Useable
      cell = document.createElement('TD');
      cell.className = 'cell-mono cell-range';
      cell.textContent = rangeText;
      newRow.appendChild(cell);

      // Hosts
      cell = document.createElement('TD');
      cell.className = 'cell-hosts';
      cell.textContent = numHosts.toLocaleString();
      newRow.appendChild(cell);

      // Divide action
      cell = document.createElement('TD');
      newRow.appendChild(cell);

      if (mask == 32 || isExcluded(address, mask)) {
        var span = document.createElement('SPAN');
        span.className = 'action-link action-disabled';
        span.innerHTML = ICON_PLUS + ' Divide';
        cell.appendChild(span);
      } else {
        var link = document.createElement('A');
        link.className = 'action-link';
        link.href = '#';
        link.onclick = function (n) { return function () { divide(n); return false; }; }(node);
        link.innerHTML = ICON_PLUS + ' Divide';
        cell.appendChild(link);
      }

      // Join column (mask badges)
      var colspan = depth - node[0];

      for (var i = (labels.length / 3) - 1; i >= 0; i--) {
        var labelMask = labels[i * 3];
        var rowspan = labels[(i * 3) + 1];
        var joinnode = labels[(i * 3) + 2];

        cell = document.createElement('TD');
        cell.rowSpan = (rowspan > 1 ? rowspan : 1);
        cell.colSpan = (colspan > 1 ? colspan : 1);
        cell.className = 'mask-cell mask-' + labelMask;

        if (i != (labels.length / 3) - 1) {
          cell.classList.add('joinable');
          cell.onclick = newJoin(joinnode);
          cell.title = 'Join: ' + inet_ntoa(network_address(address, labelMask)) + '/' + labelMask;
        }

        cell.textContent = '/' + labelMask;
        newRow.appendChild(cell);

        colspan = 1;
      }
    }
  }

  // =====================
  // Initialization
  // =====================

  function calcOnLoad() {
    var form = document.getElementById('calcForm');
    var args = parseQueryString();
    if (args['network'] && args['mask'] && args['division']) {
      form.elements['network'].value = args['network'];
      form.elements['netbits'].value = args['mask'];
      if (args['exclusions']) {
        form.elements['exclusions'].value = args['exclusions'];
      }
      updateNetwork();
      if (!rootSubnet) return;     // the link's network or mask didn't parse: its message is showing
      var division = asciiToBin(args['division']);
      rootSubnet = [0, 0, null];
      if (division != '0') {
        loadNode(rootSubnet, division);
      }
      recreateTables();
    } else {
      updateNetwork();
    }
  }

  document.getElementById('calcForm').addEventListener('submit', function (e) {
    e.preventDefault();
    updateNetwork();
  });

  // Reset: app.js asks on the first submit (and prevents it); the confirmed resubmit reaches here unprevented
  document.addEventListener('submit', function (e) {
    if (e.target.id !== 'calc-reset') return;
    var asking = e.defaultPrevented;      // the first submit: app.js stopped it to ask
    e.preventDefault();                   // the form never goes anywhere
    if (!asking) startOver();
  });

  document.getElementById('copyBtn').addEventListener('click', copyTable);

  var rangeHeader = document.getElementById('rangeHeader');
  rangeHeader.addEventListener('click', toggleRangeMode);
  rangeHeader.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleRangeMode(); }
  });

  calcOnLoad();
})();

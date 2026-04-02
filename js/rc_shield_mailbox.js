(function (window, document) {
  'use strict';

  var RCS = window.RCS || {};
  var env = RCS.env || {};

  function visibleUids() {
    if (Array.isArray(window.rcmail && window.rcmail.env && window.rcmail.env.rcs_visible_uids)) {
      return window.rcmail.env.rcs_visible_uids.filter(Boolean);
    }

    var rows = document.querySelectorAll('tr[id^="rcmrow"]');
    return Array.prototype.map.call(rows, function (row) {
      return parseInt(String(row.id).replace(/\D+/g, ''), 10) || 0;
    }).filter(Boolean);
  }

  function targetForUid(uid) {
    var row = document.getElementById('rcmrow' + uid);
    if (!row) {
      return null;
    }

    return row.querySelector('.subject')
      || row.querySelector('.fromto')
      || row.querySelector('td');
  }

  function ensurePlaceholder(uid) {
    var target = targetForUid(uid);
    if (!target || target.querySelector('.rcs-status')) {
      return;
    }

    var html = RCS.renderStatusIcon({
      level: 'unknown',
      label: (env.strings && env.strings.unknown) || 'Unknown',
      tooltip: (env.strings && env.strings.loading) || 'Analyzing message',
      score: 0
    });

    target.insertAdjacentHTML('afterbegin', html);
  }

  function updateStatus(uid, status) {
    var target = targetForUid(uid);
    if (!target) {
      return;
    }

    var existing = target.querySelector('.rcs-status');
    if (!existing) {
      ensurePlaceholder(uid);
      existing = target.querySelector('.rcs-status');
    }
    if (!existing) {
      return;
    }

    existing.outerHTML = RCS.renderStatusIcon(status);
  }

  function loadMailboxStatuses() {
    var mailbox = env.mailbox || (window.rcmail && window.rcmail.env && window.rcmail.env.rcs_visible_mailbox) || '';
    if (!env.statuses_url || !mailbox) {
      return;
    }

    var uids = visibleUids();
    if (!uids.length) {
      return;
    }

    uids.forEach(ensurePlaceholder);

    RCS.fetchJson(env.statuses_url, {
      _token: env.token || '',
      _mbox: mailbox,
      _uids: uids.join(',')
    }).then(function (json) {
      if (!json || !json.ok || !json.statuses) {
        return;
      }

      Object.keys(json.statuses).forEach(function (uid) {
        updateStatus(uid, json.statuses[uid]);
      });
    }).catch(function () {
      uids.forEach(function (uid) {
        updateStatus(uid, {
          level: 'unknown',
          label: (env.strings && env.strings.unknown) || 'Unknown',
          tooltip: 'Message analysis unavailable',
          score: 0
        });
      });
    });
  }

  if (window.rcmail) {
    window.rcmail.addEventListener('init', loadMailboxStatuses);
    window.rcmail.addEventListener('insertrow', function (evt) {
      if (evt && evt.uid) {
        ensurePlaceholder(evt.uid);
        loadMailboxStatuses();
      }
    });
  } else {
    document.addEventListener('DOMContentLoaded', loadMailboxStatuses);
  }
})(window, document);

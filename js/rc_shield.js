(function (window, document) {
  'use strict';

  var env = window.rcmail && window.rcmail.env ? window.rcmail.env.rcs || {} : {};
  var icons = env.icons || {};
  var strings = env.strings || {};

  function panelDensity() {
    return env.panel_density === 'compact' ? 'compact' : 'detailed';
  }

  function iconForLevel(level) {
    return icons[level] || icons.unknown || '';
  }

  function labelForLevel(level) {
    if (level === 'safe') return strings.safe || 'Safe';
    if (level === 'suspicious') return strings.suspicious || 'Suspicious';
    if (level === 'danger') return strings.danger || 'Dangerous';
    return strings.unknown || 'Unknown';
  }

  function escapeHtml(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fetchJson(url, payload) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'X-RCUBE-TOKEN': env.token || ''
      },
      body: new URLSearchParams(payload).toString()
    }).then(function (response) {
      if (!response.ok) {
        throw new Error('HTTP ' + response.status);
      }
      return response.json();
    });
  }

  function renderStatusIcon(status) {
    var level = status.level || 'unknown';
    var label = escapeHtml(status.label || labelForLevel(level));
    var tooltip = escapeHtml(status.tooltip || label);
    var icon = escapeHtml(iconForLevel(level));
    var score = typeof status.score === 'number' ? status.score : 0;

    return [
      '<span class="rcs-status rcs-status--' + escapeHtml(level) + '"',
      ' data-level="' + escapeHtml(level) + '"',
      ' data-score="' + String(score) + '"',
      ' title="' + tooltip + '"',
      ' aria-label="' + label + ': ' + String(score) + '"',
      ' role="img">',
      '<img src="' + icon + '" alt="" />',
      '<span class="rcs-status__text">' + label + '</span>',
      '</span>'
    ].join('');
  }

  function renderAnalysisPanel(analysis) {
    var status = analysis.status || {};
    var scoreMeta = analysis.score || {};
    var domains = analysis.domains || {};
    var origin = analysis.origin || {};
    var auth = analysis.authentication || {};
    var reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
    var technical = analysis.technical || {};
    var meter = Math.max(0, Math.min(100, status.score || 0));
    var details = escapeHtml(JSON.stringify(technical, null, 2));
    var level = status.level || 'unknown';
    var label = status.label || labelForLevel(level);
    var icon = escapeHtml(iconForLevel(level));
    var mismatch = domains.reply_to_mismatch || domains.return_path_mismatch;
    var density = panelDensity();
    var isCompact = density === 'compact';

    var gridItems = [
      ['SPF', (auth.spf && auth.spf.result) || 'none'],
      ['DKIM', (auth.dkim && auth.dkim.result) || 'none'],
      ['DMARC', (auth.dmarc && auth.dmarc.result) || 'none'],
      ['From', domains.from || ''],
      ['Reply-To', domains.reply_to || ''],
      ['Return-Path', domains.return_path || ''],
      ['Origin IP', origin.ip || ''],
      ['Reverse DNS', origin.rdns || ''],
      ['Country', origin.country || '']
    ];

    if (isCompact) {
      gridItems = gridItems.filter(function (item) {
        return item[1];
      }).slice(0, 6);
    }

    var gridHtml = gridItems.map(function (item) {
      return '<div><span>' + escapeHtml(item[0]) + '</span><strong>' + escapeHtml(item[1]) + '</strong></div>';
    }).join('');

    var reasonsHtml = reasons.length
      ? reasons.map(function (reason) {
          return '<li><strong>' + escapeHtml(reason.points) + '</strong> ' + escapeHtml(reason.message) + '</li>';
        }).join('')
      : '<li>' + escapeHtml(strings.not_available || 'Not available') + '</li>';

    var compactReasonsHtml = reasons.length
      ? reasons.slice(0, 2).map(function (reason) {
          return '<li><strong>' + escapeHtml(reason.points) + '</strong> ' + escapeHtml(reason.message) + '</li>';
        }).join('')
      : '<li>' + escapeHtml(strings.not_available || 'Not available') + '</li>';

    return [
      '<section class="rcs-popover-wrap rcs-popover-wrap--' + escapeHtml(density) + '">',
      '<button type="button" class="rcs-badge rcs-badge--' + escapeHtml(level) + ' rcs-badge--' + escapeHtml(density) + '"',
      ' aria-haspopup="true"',
      ' aria-label="' + escapeHtml(label) + ': ' + String(status.score || 0) + '"',
      ' title="' + escapeHtml(scoreMeta.summary || analysis.summary || label) + '">',
      '<img src="' + icon + '" alt="" />',
      '<span class="rcs-badge__score">' + String(status.score || 0) + '</span>',
      '<span class="rcs-badge__text">' + escapeHtml(label) + '</span>',
      '</button>',
      '<div class="rcs-popover rcs-popover--' + escapeHtml(density) + '" role="tooltip">',
      '<div class="rcs-popover__header">',
      '<div class="rcs-popover__status">' + renderStatusIcon({
        level: level,
        label: label,
        tooltip: scoreMeta.summary || analysis.summary || ''
      }) + '</div>',
      '<div class="rcs-popover__score">',
      '<div class="rcs-panel__score-label">' + escapeHtml(strings.threat_score || 'Threat Score') + '</div>',
      '<div class="rcs-panel__score-value">' + String(status.score || 0) + '</div>',
      '</div>',
      '</div>',
      '<div class="rcs-meter" aria-hidden="true"><span style="width:' + String(meter) + '%"></span></div>',
      '<p class="rcs-panel__summary">' + escapeHtml(analysis.summary || scoreMeta.summary || '') + '</p>',
      '<div class="rcs-grid rcs-grid--' + escapeHtml(density) + '">' + gridHtml + '</div>',
      mismatch
        ? '<div class="rcs-warning">Domain mismatch detected between sender identity headers.</div>'
        : '',
      isCompact
        ? '<div class="rcs-panel__section rcs-panel__section--compact"><h4>Signals</h4><ul class="rcs-reasons">' + compactReasonsHtml + '</ul></div>'
        : '<div class="rcs-panel__section"><h4>Reasons</h4><ul class="rcs-reasons">' + reasonsHtml + '</ul></div>',
      isCompact
        ? ''
        : '<details class="rcs-details"><summary>' + escapeHtml(strings.technical_details || 'Technical details') + '</summary><pre>' + details + '</pre></details>',
      '</div>',
      '</section>'
    ].join('');
  }

  function loadAnalysisPanels() {
    if (!env.analysis_url) {
      return;
    }

    var nodes = document.querySelectorAll('.rcs-analysis-placeholder');
    Array.prototype.forEach.call(nodes, function (node) {
      if (node.dataset.loaded === '1') {
        return;
      }

      node.dataset.loaded = '1';

      fetchJson(env.analysis_url, {
        _token: env.token || '',
        _uid: node.getAttribute('data-uid') || '',
        _mbox: node.getAttribute('data-mbox') || env.mailbox || ''
      }).then(function (json) {
        if (!json || !json.ok || !json.analysis) {
          throw new Error('invalid analysis payload');
        }

        node.innerHTML = renderAnalysisPanel(json.analysis);
      }).catch(function () {
        node.innerHTML = '<span class="rcs-analysis-error" title="Analysis unavailable">!</span>';
      });
    });
  }

  window.RCS = window.RCS || {};
  window.RCS.env = env;
  window.RCS.iconForLevel = iconForLevel;
  window.RCS.labelForLevel = labelForLevel;
  window.RCS.renderStatusIcon = renderStatusIcon;
  window.RCS.fetchJson = fetchJson;
  window.RCS.loadAnalysisPanels = loadAnalysisPanels;

  if (window.rcmail) {
    window.rcmail.addEventListener('init', loadAnalysisPanels);
  } else {
    document.addEventListener('DOMContentLoaded', loadAnalysisPanels);
  }
})(window, document);

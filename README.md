# RoundcubeShield

![Downloads](https://img.shields.io/github/downloads/texxasrulez/rc_shield/total?style=plastic&logo=github&logoColor=white&label=Downloads&labelColor=aqua&color=blue)
[![Packagist Downloads](https://img.shields.io/packagist/dt/texxasrulez/rc_shield?style=plastic&logo=packagist&logoColor=white&label=Downloads&labelColor=blue&color=gold)](https://packagist.org/packages/texxasrulez/rc_shield)
[![Packagist Version](https://img.shields.io/packagist/v/texxasrulez/rc_shield?style=plastic&logo=packagist&logoColor=white&label=Version&labelColor=blue&color=limegreen)](https://packagist.org/packages/texxasrulez/rc_shield)
[![Github License](https://img.shields.io/github/license/texxasrulez/rc_shield?style=plastic&logo=github&label=License&labelColor=blue&color=coral)](https://github.com/texxasrulez/rc_shield/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/texxasrulez/rc_shield?style=plastic&logo=github&label=Stars&labelColor=blue&color=deepskyblue)](https://github.com/texxasrulez/rc_shield/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/texxasrulez/rc_shield?style=plastic&logo=github&label=Issues&labelColor=blue&color=aqua)](https://github.com/texxasrulez/rc_shield/issues)
[![GitHub Contributors](https://img.shields.io/github/contributors/texxasrulez/rc_shield?style=plastic&logo=github&logoColor=white&label=Contributors&labelColor=blue&color=orchid)](https://github.com/texxasrulez/rc_shield/graphs/contributors)
[![GitHub Forks](https://img.shields.io/github/forks/texxasrulez/rc_shield?style=plastic&logo=github&logoColor=white&label=Forks&labelColor=blue&color=darkorange)](https://github.com/texxasrulez/rc_shield/forks)
[![Donate Paypal](https://img.shields.io/badge/Paypal-Money_Please!-blue.svg?style=plastic&labelColor=blue&color=forestgreen&logo=paypal)](https://www.paypal.me/texxasrulez)

RoundcubeShield is a production-oriented Roundcube plugin that analyzes real message headers, authentication results, sender identity mismatches, origin routing hints, and optional reputation data to produce a weighted threat score. It adds asynchronous mailbox threat indicators and a message-view analysis panel without blocking mail rendering.

## Features

- Real Roundcube plugin integration through `rcube_plugin`, hooks, and registered plugin actions.
- Async mailbox threat icons with `Safe`, `Suspicious`, `Dangerous`, and `Unknown` states.
- Message analysis panel with threat score, threat meter, authentication results, sender/domain mismatch details, origin IP, reverse DNS, geolocation summary, reputation status, reasons, and technical details.
- Header parsing for `Authentication-Results`, `Received`, `DKIM-Signature`, `Return-Path`, `Reply-To`, `From`, `Message-ID`, and selected `X-*` headers.
- Weighted scoring engine with configurable thresholds and rule weights.
- Provider architecture for local intelligence, DNSBL, and explicitly allowlisted external HTTP adapters.
- Database-backed caching for analysis and reputation lookups.
- Optional admin cache purge endpoint.
- User preferences for mailbox icons, tooltips, and compact vs detailed panel display.

<<<<<<< Updated upstream
=======
**Screenshot**
-----------

![Alt text](images/screenshot.png?raw=true "RoundcubeShield Screenshot")


>>>>>>> Stashed changes
## Supported Skins

- `elastic`
- `classic`
- `larry`
- `autumn_larry`
- `black_larry`
- `blue_larry`
- `green_larry`
- `grey_larry`
- `pink_larry`
- `plata_larry`
- `summer_larry`
- `teal_larry`
- `violet_larry`

Larry color variants reuse the base `larry` skin assets and only ship minimal wrapper styles.

## Installation

1. Copy `plugins/rc_shield` into the Roundcube plugin directory.
2. Apply the SQL schema matching your Roundcube database engine from `plugins/rc_shield/SQL/`.
3. Add `rc_shield` to `config/config.inc.php` in the Roundcube plugins array.
4. Copy `plugins/rc_shield/config.inc.php.dist` to `plugins/rc_shield/config.inc.php` and adjust site-specific settings.
5. Clear Roundcube caches and reload the mail UI.

## Configuration

Core configuration lives in `config.inc.php`:

```php
$config['rcs_enable_geo'] = true;
$config['rcs_enable_dns'] = true;
$config['rcs_enable_external_reputation'] = false;
$config['rcs_cache_ttl_analysis'] = 86400;
$config['rcs_cache_ttl_reputation'] = 43200;
$config['rcs_score_threshold_safe_max'] = 30;
$config['rcs_score_threshold_suspicious_max'] = 70;
$config['rcs_weight_spf_fail'] = 30;
$config['rcs_weight_dkim_fail'] = 25;
$config['rcs_weight_dmarc_fail'] = 25;
$config['rcs_weight_replyto_mismatch'] = 20;
```

Important security-related config:

- `rcs_allowed_http_hosts`: allowlist of external reputation service hosts.
- `rcs_http_providers`: static provider adapter definitions.
- `rcs_allowlisted_domains`, `rcs_allowlisted_emails`, `rcs_allowlisted_ip_ranges`.
- `rcs_blocklisted_domains`, `rcs_blocklisted_ips`.
- `rcs_trusted_mta_networks`.
- `rcs_admin_user_ids`.
- `rcs_debug`.

## Provider Architecture

RoundcubeShield separates analysis from enrichment:

- `rcs_provider_local`: local allowlist/blocklist logic, reverse DNS, reserved/private IP detection, and basic geo placeholder behavior.
- `rcs_provider_dnsbl`: DNSBL-style reputation checks using configured zones.
- `rcs_provider_generic_http`: optional HTTPS JSON adapter with strict host allowlisting.

External provider calls are optional. If disabled or unavailable, analysis still completes from local header evidence.

## Scoring Model

Scoring is additive and configurable. Default thresholds:

- `0-30`: Safe
- `31-70`: Suspicious
- `71+`: Dangerous

Current default rule categories include:

- SPF fail, softfail, or none.
- DKIM fail or none.
- DMARC fail or none.
- From vs Reply-To mismatch.
- From vs Return-Path mismatch.
- Suspicious HELO.
- Missing reverse DNS.
- Reputation blocklist hit.
- Private/reserved origin IP.
- Malformed or missing critical headers.
- Trusted sender deduction.
- Trusted network deduction.

All rules emit machine-readable reason codes and human-readable messages.

## Cache Behavior

`rcs_cache` stores JSON payloads keyed by:

- cache scope
- mailbox
- UID
- message identity hash
- analysis version salt

Cache scopes used now:

- `analysis`
- `reputation`
- `headers`

Analysis is invalidated automatically when the message identity hash changes or when `rcs_analysis_version` changes.

## Security Model

- Every AJAX endpoint validates the Roundcube request token.
- Mailbox names and UIDs are normalized and bounded before use.
- Only Roundcube plugin actions are used; there are no direct-access PHP endpoints.
- UI output is escaped before client-side rendering and sanitized through fixed server response shapes.
- External HTTP lookups are disabled by default.
- External HTTP providers require explicit HTTPS URLs and explicit host allowlisting.
- No shell execution, dynamic routing files, eval, or unsafe deserialization are used.
- Provider failures, parsing gaps, and cache misses fail gracefully and return `Unknown` or partial analysis instead of breaking mail views.

## Performance Notes

- Mailbox pages do not perform synchronous remote analysis during initial HTML render.
- The mailbox view only analyzes visible message UIDs received from the real `messages_list` hook.
- Bulk mailbox status requests are batched through one plugin action.
- Analysis and reputation data are cached aggressively.
- Message detail panels lazy-load after the Roundcube page initializes.

## Integration Map

### Hooks

- `add_hook('storage_init', ...)`
  Ensures relevant headers are fetched by Roundcube storage.
- `add_hook('messages_list', ...)`
  Captures real visible message UIDs from the active mailbox page and exposes them to mailbox JS.
- `add_hook('message_load', ...)`
  Captures the active message UID and mailbox from the real Roundcube message object.
- `add_hook('message_headers_output', ...)`
  Injects a real message-view placeholder into the message headers area.
- `add_hook('template_object_messagesummary', ...)`
  Appends the analysis placeholder to message summary content when needed across skins.
- `add_hook('render_page', ...)`
  Loads JS/CSS only for the mail task and exports runtime URLs, icons, strings, token, mailbox, and UID.
- `add_hook('preferences_sections_list', ...)`
  Adds a Roundcube settings section for presentation preferences.
- `add_hook('preferences_list', ...)`
  Renders safe user-facing preferences.
- `add_hook('preferences_save', ...)`
  Validates and stores user-facing preferences.

### Actions

- `register_action('plugin.rc_shield.statuses', ...)`
  Returns bulk mailbox threat states for visible UIDs.
- `register_action('plugin.rc_shield.analysis', ...)`
  Returns detailed message analysis JSON for a specific UID and mailbox.
- `register_action('plugin.rc_shield.cache_purge', ...)`
  Purges plugin caches for configured admin users.

### Asset Loading

- `styles/variables.css`: mail task, all supported skins.
- `styles/common.css`: mail task, all supported skins.
- `skins/<skin>/styles/rc_shield.css`: mail task, selected skin wrapper.
- `js/rc_shield.js`: mail task, provides shared namespace, fetch helper, and message panel loader.
- `js/rc_shield_mailbox.js`: mail task, mailbox icon placeholder insertion and batched status fetch.

### Runtime Data Flow

- Mailbox view gets real message UIDs from `messages_list`, not from fake demo rows.
- Mailbox JS reads those UIDs, inserts an `Unknown` placeholder icon, and requests statuses from `plugin.rc_shield.statuses`.
- Message analysis reads real message context through `rcube_message` and Roundcube storage methods such as `get_raw_message()` or `get_raw_headers()` when available.
- Parser, reputation providers, scoring, and cache operate entirely in the plugin runtime path.
- Optional provider adapters are extension points; core parsing and scoring remain local runtime logic.

## Security Notes

### Input Validation Strategy

- UIDs are converted to positive integers only.
- Mailbox names are stripped of control characters and length-bounded.
- Batch UID lists are deduplicated and size-limited.
- Request tokens are required for every JSON action.

### Output Escaping Strategy

- Server-generated HTML placeholders are built from fixed plugin strings.
- Client rendering escapes dynamic text before DOM insertion.
- JSON responses expose only structured analysis fields required by the UI.

### SSRF Protections

- Generic HTTP providers are disabled by default.
- Only HTTPS endpoints are accepted.
- Provider hosts must match `rcs_allowed_http_hosts`.
- URLs come only from static admin configuration, never from user input.
- Redirects are disabled for external HTTP lookups.

### Permission Boundaries

- Endpoints run within the authenticated Roundcube session.
- Cache purge is limited to configured admin user IDs.
- User preferences cover presentation only, not provider or risk model settings.

### Failure Behavior

- Parsing failures add warnings and degrade to partial analysis.
- Provider exceptions are caught and isolated.
- Unavailable analysis returns `Unknown` or a non-fatal error panel.
- Mailbox rendering does not block on provider latency.

## Future Extension Points

- Additional provider adapters implementing `rcs_provider_interface`.
- Site-specific webhook intelligence adapters.
- Extra scoring rules inside `rcs_scoring`.
- More advanced geolocation providers.
- Policy-aware trusted sender models.

## Screenshots

- Mailbox threat icons: placeholder
- Message analysis panel: placeholder
- Settings section: placeholder

## Upgrade Notes

- Apply schema updates when moving between plugin versions that alter `rcs_cache`.
- Bump `rcs_analysis_version` to invalidate old cached analysis after changing scoring or parsing behavior.
- Review `rcs_allowed_http_hosts` and `rcs_http_providers` carefully before enabling external reputation.

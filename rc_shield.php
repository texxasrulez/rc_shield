<?php

require_once __DIR__ . '/lib/rcs_provider_interface.php';
require_once __DIR__ . '/lib/rcs_helpers.php';
require_once __DIR__ . '/lib/rcs_cache.php';
require_once __DIR__ . '/lib/rcs_dns.php';
require_once __DIR__ . '/lib/rcs_geo.php';
require_once __DIR__ . '/lib/providers/rcs_provider_local.php';
require_once __DIR__ . '/lib/providers/rcs_provider_dnsbl.php';
require_once __DIR__ . '/lib/providers/rcs_provider_generic_http.php';
require_once __DIR__ . '/lib/rcs_reputation.php';
require_once __DIR__ . '/lib/rcs_header_parser.php';
require_once __DIR__ . '/lib/rcs_scoring.php';
require_once __DIR__ . '/lib/rcs_storage.php';
require_once __DIR__ . '/lib/rcs_analyzer.php';
require_once __DIR__ . '/lib/rcs_controller.php';

class rc_shield extends rcube_plugin
{
    public $task = 'mail|settings';
    public $version = '1.0.0';

    private rcmail $rcmail;
    private rcs_controller $controller;
    private ?int $current_uid = null;
    private ?string $current_mailbox = null;

    public function init(): void
    {
        $this->rcmail = rcmail::get_instance();
        $this->load_config();
        $this->add_texts('localization/', true);

        $cache = new rcs_cache($this->rcmail->db, $this->rcmail->config);
        $storage = new rcs_storage($this->rcmail);
        $parser = new rcs_header_parser();
        $reputation = new rcs_reputation(
            [
                new rcs_provider_local($this->rcmail->config, new rcs_dns(), new rcs_geo()),
                new rcs_provider_dnsbl($this->rcmail->config, new rcs_dns()),
                new rcs_provider_generic_http($this->rcmail->config),
            ],
            $cache,
            $this->rcmail->config
        );
        $analyzer = new rcs_analyzer(
            $parser,
            $reputation,
            new rcs_scoring($this->rcmail->config),
            $cache,
            $this->rcmail->config,
            rcube::get_instance()
        );

        $this->controller = new rcs_controller(
            $this->rcmail,
            $this,
            $storage,
            $analyzer,
            $cache,
            $this->rcmail->config
        );

        $this->add_hook('storage_init', [$this, 'storage_init']);
        $this->add_hook('messages_list', [$this, 'messages_list']);
        $this->add_hook('message_load', [$this, 'message_load']);
        $this->add_hook('message_headers_output', [$this, 'message_headers_output']);
        $this->add_hook('template_object_messagesummary', [$this, 'message_summary']);
        $this->add_hook('render_page', [$this, 'render_page']);

        if ($this->rcmail->task === 'settings') {
            $this->add_hook('preferences_sections_list', [$this, 'preferences_sections_list']);
            $this->add_hook('preferences_list', [$this, 'preferences_list']);
            $this->add_hook('preferences_save', [$this, 'preferences_save']);
        }

        $this->register_action('plugin.rc_shield.statuses', [$this->controller, 'action_statuses']);
        $this->register_action('plugin.rc_shield.analysis', [$this->controller, 'action_analysis']);
        $this->register_action('plugin.rc_shield.cache_purge', [$this->controller, 'action_purge_cache']);
    }

    /**
     * Ensure relevant anti-abuse headers are available even in list view.
     *
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function storage_init(array $args): array
    {
        $extra = [
            'AUTHENTICATION-RESULTS',
            'RECEIVED',
            'DKIM-SIGNATURE',
            'RETURN-PATH',
            'REPLY-TO',
            'MESSAGE-ID',
        ];

        $existing = trim((string) ($args['fetch_headers'] ?? ''));
        $args['fetch_headers'] = trim($existing . ' ' . implode(' ', $extra));

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function messages_list(array $args): array
    {
        if ($this->rcmail->task !== 'mail' || !$this->get_user_pref_bool('rcs_show_mailbox_icons', true)) {
            return $args;
        }

        $mailbox = rcs_helpers::sanitize_mailbox((string) rcube_utils::get_input_value('_mbox', rcube_utils::INPUT_GPC));
        $uids = [];

        foreach ((array) ($args['messages'] ?? []) as $message) {
            $uid = rcs_helpers::sanitize_uid($message->uid ?? 0);
            if ($uid > 0) {
                $uids[] = $uid;
            }
        }

        $this->rcmail->output->set_env('rcs_visible_uids', $uids);
        $this->rcmail->output->set_env('rcs_visible_mailbox', $mailbox);

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function message_load(array $args): array
    {
        $message = $args['object'] ?? null;
        $this->current_uid = $message && !empty($message->uid)
            ? (int) $message->uid
            : rcs_helpers::sanitize_uid(rcube_utils::get_input_value('_uid', rcube_utils::INPUT_GPC));
        $this->current_mailbox = $message && !empty($message->folder)
            ? rcs_helpers::sanitize_mailbox((string) $message->folder)
            : rcs_helpers::sanitize_mailbox((string) rcube_utils::get_input_value('_mbox', rcube_utils::INPUT_GPC));

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function message_headers_output(array $args): array
    {
        if ($this->rcmail->task !== 'mail' || $this->current_uid === null || $this->current_mailbox === null) {
            return $args;
        }

        $args['output']['rcs_analysis'] = [
            'title' => rcube::Q($this->gettext('message_analysis')),
            'value' => $this->analysis_placeholder_html($this->current_uid, $this->current_mailbox),
            'html' => true,
        ];

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function message_summary(array $args): array
    {
        if (
            $this->rcmail->task !== 'mail'
            || $this->current_uid === null
            || $this->current_mailbox === null
            || $this->resolve_skin() !== 'elastic'
        ) {
            return $args;
        }

        $content = (string) ($args['content'] ?? '');
        if (str_contains($content, 'rcs-analysis-placeholder')) {
            return $args;
        }

        $args['content'] = $content . $this->analysis_placeholder_html($this->current_uid, $this->current_mailbox);
        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function render_page(array $args): array
    {
        if (!in_array($this->rcmail->task, ['mail', 'settings'], true)) {
            return $args;
        }

        $skin = $this->resolve_skin();
        $skinPath = $this->skin_stylesheet_path($skin);
        $this->include_stylesheet('styles/variables.css');
        $this->include_stylesheet('styles/common.css');
        $this->include_stylesheet($skinPath);

        if ($this->rcmail->task === 'mail') {
            $this->include_script('js/rc_shield.js');

            if ($this->get_user_pref_bool('rcs_show_mailbox_icons', true)) {
                $this->include_script('js/rc_shield_mailbox.js');
            }

            $this->rcmail->output->set_env('rcs', [
                'token' => method_exists($this->rcmail, 'get_request_token') ? (string) $this->rcmail->get_request_token() : '',
                'mailbox' => rcs_helpers::sanitize_mailbox((string) rcube_utils::get_input_value('_mbox', rcube_utils::INPUT_GPC)),
                'uid' => rcs_helpers::sanitize_uid(rcube_utils::get_input_value('_uid', rcube_utils::INPUT_GPC)),
                'show_tooltips' => $this->get_user_pref_bool('rcs_show_tooltips', true),
                'panel_density' => (string) $this->rcmail->config->get('rcs_panel_density', $this->rcmail->config->get('preferences.rcs_panel_density', 'detailed')),
                'statuses_url' => $this->mail_url(['_action' => 'plugin.rc_shield.statuses']),
                'analysis_url' => $this->mail_url(['_action' => 'plugin.rc_shield.analysis']),
                'icons' => [
                    'safe' => $this->icon_url('images/rcs_safe.svg'),
                    'suspicious' => $this->icon_url('images/rcs_warn.svg'),
                    'danger' => $this->icon_url('images/rcs_danger.svg'),
                    'unknown' => $this->icon_url('images/rcs_unknown.svg'),
                ],
                'strings' => [
                    'safe' => $this->gettext('safe'),
                    'suspicious' => $this->gettext('suspicious'),
                    'danger' => $this->gettext('danger'),
                    'unknown' => $this->gettext('unknown'),
                    'loading' => $this->gettext('loading'),
                    'threat_score' => $this->gettext('threat_score'),
                    'message_analysis' => $this->gettext('message_analysis'),
                    'header_intelligence' => $this->gettext('header_intelligence'),
                    'summary' => $this->gettext('summary'),
                    'technical_details' => $this->gettext('technical_details'),
                    'not_available' => $this->gettext('not_available'),
                ],
            ]);
        }

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function preferences_sections_list(array $args): array
    {
        $args['list']['rc_shield'] = [
            'id' => 'rc_shield',
            'class' => 'rc_shield',
            'section' => rcube_utils::rep_specialchars_output($this->gettext('section_title')),
        ];

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function preferences_list(array $args): array
    {
        if (($args['section'] ?? '') !== 'rc_shield') {
            return $args;
        }

        $showIcons = $this->get_user_pref_bool('rcs_show_mailbox_icons', true);
        $showTooltips = $this->get_user_pref_bool('rcs_show_tooltips', true);
        $panelDensity = (string) $this->rcmail->config->get(
            'rcs_panel_density',
            $this->rcmail->config->get('preferences.rcs_panel_density', 'detailed')
        );

        $args['blocks']['rc_shield'] = [
            'name' => rcube_utils::rep_specialchars_output($this->gettext('plugin_title')),
            'options' => [],
        ];

        $checkbox = new html_checkbox(['name' => '_rcs_show_mailbox_icons', 'value' => 1, 'id' => 'rcs_show_mailbox_icons']);
        $args['blocks']['rc_shield']['options']['show_mailbox_icons'] = [
            'title' => rcube_utils::rep_specialchars_output($this->gettext('show_mailbox_icons')),
            'content' => $checkbox->show($showIcons),
        ];

        $checkbox = new html_checkbox(['name' => '_rcs_show_tooltips', 'value' => 1, 'id' => 'rcs_show_tooltips']);
        $args['blocks']['rc_shield']['options']['show_tooltips'] = [
            'title' => rcube_utils::rep_specialchars_output($this->gettext('show_tooltips')),
            'content' => $checkbox->show($showTooltips),
        ];

        $select = new html_select(['name' => '_rcs_panel_density', 'id' => 'rcs_panel_density']);
        $select->add($this->gettext('panel_density_compact'), 'compact');
        $select->add($this->gettext('panel_density_detailed'), 'detailed');

        $args['blocks']['rc_shield']['options']['panel_density'] = [
            'title' => rcube_utils::rep_specialchars_output($this->gettext('panel_density')),
            'content' => $select->show($panelDensity),
        ];

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function preferences_save(array $args): array
    {
        if (($args['section'] ?? '') !== 'rc_shield') {
            return $args;
        }

        $density = (string) rcube_utils::get_input_value('_rcs_panel_density', rcube_utils::INPUT_POST);
        if (!in_array($density, ['compact', 'detailed'], true)) {
            $density = 'detailed';
        }

        $args['prefs']['rcs_show_mailbox_icons'] = rcube_utils::get_input_value('_rcs_show_mailbox_icons', rcube_utils::INPUT_POST) ? true : false;
        $args['prefs']['rcs_show_tooltips'] = rcube_utils::get_input_value('_rcs_show_tooltips', rcube_utils::INPUT_POST) ? true : false;
        $args['prefs']['rcs_panel_density'] = $density;

        return $args;
    }

    private function analysis_placeholder_html(int $uid, string $mailbox): string
    {
        return html::div(
            [
                'class' => 'rcs-analysis-placeholder',
                'data-uid' => $uid,
                'data-mbox' => $mailbox,
                'aria-live' => 'polite',
            ],
            html::span(
                [
                    'class' => 'rcs-analysis-loading',
                    'title' => rcube::Q($this->gettext('loading')),
                    'aria-label' => rcube::Q($this->gettext('loading')),
                ],
                '...'
            )
        );
    }

    private function get_user_pref_bool(string $name, bool $default): bool
    {
        return (bool) $this->rcmail->config->get($name, $default);
    }

    private function resolve_skin(): string
    {
        $skin = str_replace('-', '_', (string) $this->rcmail->config->get('skin', 'elastic'));
        $supported = [
            'classic',
            'elastic',
            'larry',
            'autumn_larry',
            'black_larry',
            'blue_larry',
            'green_larry',
            'grey_larry',
            'pink_larry',
            'plata_larry',
            'summer_larry',
            'teal_larry',
            'violet_larry',
        ];

        return in_array($skin, $supported, true) ? $skin : 'elastic';
    }

    private function skin_stylesheet_path(string $skin): string
    {
        return 'skins/' . $skin . '/styles/rc_shield.css';
    }

    /**
     * @param array<string, scalar> $params
     */
    private function mail_url(array $params): string
    {
        if (!isset($params['_task'])) {
            $params['_task'] = 'mail';
        }

        if (!isset($params['_token']) && method_exists($this->rcmail, 'get_request_token')) {
            $params['_token'] = (string) $this->rcmail->get_request_token();
        }

        if (method_exists($this->rcmail, 'url')) {
            return $this->rcmail->url($params);
        }

        return './?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    private function asset_url(string $path): string
    {
        $path = ltrim($path, '/');

        $url = '';

        if (method_exists($this, 'url')) {
            $url = (string) $this->url($path);
        } else {
            $url = './plugins/rc_shield/' . $path;
        }

        if (preg_match('/^(?:[a-z][a-z0-9+.-]*:|\\/)/i', $url)) {
            return $url;
        }

        if (isset($this->rcmail->output) && method_exists($this->rcmail->output, 'abs_url')) {
            return (string) $this->rcmail->output->abs_url($url);
        }

        return $url;
    }

    private function icon_url(string $path): string
    {
        $path = ltrim($path, '/');
        $fullPath = __DIR__ . '/' . $path;

        if (is_readable($fullPath) && str_ends_with(strtolower($path), '.svg')) {
            $svg = file_get_contents($fullPath);

            if (is_string($svg) && $svg !== '') {
                return 'data:image/svg+xml;charset=UTF-8,' . rawurlencode($svg);
            }
        }

        return $this->asset_url($path);
    }
}

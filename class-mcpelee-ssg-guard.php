<?php
if (!defined('ABSPATH')) { exit; }
final class MCPELEE_SSG_Guard {
    // Internal database schema revision; independent of the public release version.
    const VERSION = '2';
    public static function defaults() {
        return array('country_enabled' => 0, 'country_blocked' => array(), 'country_allowed' => array(), 'country_env' => 'MM_COUNTRY_CODE', 'blocked' => array(), 'allowed' => array(), 'access_log' => 0, 'country_lookup' => 0, 'headers' => 1, 'xmlrpc' => 0, 'hide_users' => 0, 'login_limit' => 1, 'daily_scan' => 0, 'retention' => 7);
    }
    public static function settings() { return array_merge(self::defaults(), get_option('mcpelee_ssg_settings', array())); }
    public static function ip() {
        // Only the webserver may resolve trusted proxies. X-Forwarded-For is attacker-controlled here.
        $ip = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? inet_ntop(inet_pton($ip)) : '';
    }
    public static function table($suffix) { global $wpdb; return $wpdb->prefix . 'mcpelee_ssg_' . $suffix; }
    public static function activate($network_wide = false) {
        if ($network_wide || is_multisite()) {
            wp_die('Site Security Guard는 현재 단일 사이트 활성화만 지원합니다.');
        }
        if (class_exists('MCPELEE_SSG_Migration')) { MCPELEE_SSG_Migration::run(); }
        self::install();
        if (get_option('mcpelee_ssg_version') !== self::VERSION) { wp_die('보안 데이터 테이블을 생성하지 못했습니다. DB 권한을 확인하세요.'); }
        try {
            $existing = is_file(ABSPATH . '.htaccess') ? file_get_contents(ABSPATH . '.htaccess') : '';
            if ($existing === false) { throw new RuntimeException('.htaccess 읽기 실패'); }
            if (self::settings()['blocked'] || self::settings()['country_enabled'] || (strpos($existing, '# BEGIN Site Security Guard') !== false || strpos($existing, '# BEGIN MCPELEE Site Security Guard') !== false)) {
                self::save_apache(self::settings());
            }
        } catch (Throwable $e) { wp_die(esc_html($e->getMessage())); }
        self::schedule();
    }
    public static function deactivate() {
        // Remove server rules first: disabling PHP alone would leave the site blocked.
        try { self::write_apache(''); }
        catch (Throwable $e) { wp_die(esc_html('비활성화를 중단했습니다. ' . $e->getMessage() . ' .htaccess의 Site Security Guard 구간을 수동 제거한 후 다시 시도하세요.')); }
        foreach (array('mcpelee_ssg_cleanup', 'mcpelee_ssg_daily_scan', 'mcpelee_ssg_scan_step') as $hook) { wp_clear_scheduled_hook($hook); }
        // Keep settings, events and file baselines for the next activation.
    }
    public static function schedule() {
        if (!wp_next_scheduled('mcpelee_ssg_cleanup')) { wp_schedule_event(time() + 300, 'hourly', 'mcpelee_ssg_cleanup'); }
        if (!wp_next_scheduled('mcpelee_ssg_daily_scan')) { wp_schedule_event(time() + 86400, 'daily', 'mcpelee_ssg_daily_scan'); }
        if (get_option('mcpelee_ssg_scan_state') && !wp_next_scheduled('mcpelee_ssg_scan_step')) { wp_schedule_single_event(time() + 10, 'mcpelee_ssg_scan_step'); }
    }
    public static function boot() {
        add_action('init', array(__CLASS__, 'install'), 0);
        add_action('init', array(__CLASS__, 'protect'), 1);
        add_action('admin_menu', function () { add_options_page('Site Security Guard', 'Site Security Guard', 'manage_options', 'site-security-guard', array(__CLASS__, 'page')); });
        add_action('admin_enqueue_scripts', function ($hook) {
            if ($hook === 'settings_page_site-security-guard') { wp_enqueue_style('mcpelee-ssg-admin', plugins_url('assets/mcpelee-ssg-admin.css', MCPELEE_SSG_PLUGIN_FILE), array(), '1.0.0');
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation/filtering; mutations have separate nonce checks.
                if (sanitize_key(wp_unslash($_GET['tab'] ?? '')) === 'logs') {
                    wp_enqueue_script('mcpelee-ssg-preferences', plugins_url('assets/mcpelee-ssg-preferences.js', MCPELEE_SSG_PLUGIN_FILE), array(), '1.0.0', true);
                    wp_localize_script('mcpelee-ssg-preferences', 'mcpeleeSsgPreferences', array('url'=>admin_url('admin-ajax.php'), 'nonce'=>wp_create_nonce('mcpelee_ssg_preferences')));
                    wp_enqueue_script('mcpelee-ssg-country', plugins_url('assets/mcpelee-ssg-country.js', MCPELEE_SSG_PLUGIN_FILE), array(), '1.0.0', true);
                    wp_localize_script('mcpelee-ssg-country', 'mcpeleeSsgCountry', array('url' => admin_url('admin-ajax.php'), 'nonce' => wp_create_nonce('mcpelee_ssg_country'), 'enabled' => (bool)self::settings()['country_lookup']));
                }
            }
        });
        add_action('wp_ajax_mcpelee_ssg_country', array('MCPELEE_SSG_Country', 'ajax'));
        add_action('admin_post_mcpelee_ssg_action', array(__CLASS__, 'action'));
        add_action('wp_login_failed', array(__CLASS__, 'login_failed'));
        add_action('wp_login', function () { self::log('login_success', '로그인 성공'); }, 10, 0);
        add_action('shutdown', array(__CLASS__, 'access_log'));
        add_action('mcpelee_ssg_cleanup', array(__CLASS__, 'cleanup'));
        add_action('mcpelee_ssg_scan_step', array('MCPELEE_SSG_Scanner', 'step'));
        add_action('mcpelee_ssg_daily_scan', function () { if (self::settings()['daily_scan']) { MCPELEE_SSG_Scanner::start(); } });
        add_filter('authenticate', array(__CLASS__, 'authenticate'), 100, 3);
        add_filter('rest_endpoints', function ($endpoints) {
            if (self::settings()['hide_users'] && !current_user_can('list_users')) {
                foreach (array_keys($endpoints) as $key) { if (preg_match('~^/wp/v2/users(?:/|$)~', $key)) { unset($endpoints[$key]); } }
            }
            return $endpoints;
        });
    }
    public static function install() {
        if (get_option('mcpelee_ssg_version') === self::VERSION) { return; }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate(); $events = self::table('events'); $files = self::table('files');
        dbDelta("CREATE TABLE $events (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            created_at datetime NOT NULL,
            kind varchar(32) NOT NULL,
            ip varchar(45) NOT NULL DEFAULT '',
            detail text NOT NULL,
            PRIMARY KEY  (id),
            KEY created_at (created_at),
            KEY ip (ip),
            KEY kind_ip_time (kind,ip,created_at)
        ) $charset;");
        dbDelta("CREATE TABLE $files (
            path_key char(64) NOT NULL,
            path text NOT NULL,
            digest char(64) NOT NULL,
            seen char(36) NOT NULL,
            PRIMARY KEY  (path_key),
            KEY seen (seen)
        ) $charset;");
        $countries = self::table('countries');
        dbDelta("CREATE TABLE $countries (
            ip varchar(45) NOT NULL,
            code varchar(2) NOT NULL DEFAULT '',
            name varchar(80) NOT NULL,
            expires datetime NOT NULL,
            PRIMARY KEY  (ip),
            KEY expires (expires)
        ) $charset;");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($countries))) !== $countries) { return; }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($events))) !== $events || $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($files))) !== $files) { return; }
        self::schedule();
        update_option('mcpelee_ssg_version', self::VERSION, false);
    }
    public static function log($kind, $detail) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $wpdb->insert(self::table('events'), array('created_at' => gmdate('Y-m-d H:i:s'), 'kind' => $kind, 'ip' => self::ip(), 'detail' => mb_substr($detail, 0, 2000)));
    }
    public static function cleanup() {
        global $wpdb; $table = self::table('events');
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}mcpelee_ssg_events WHERE created_at < %s", gmdate('Y-m-d H:i:s', time() - self::settings()['retention'] * DAY_IN_SECONDS)));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}mcpelee_ssg_countries WHERE expires < %s", gmdate('Y-m-d H:i:s')));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $cutoff = $wpdb->get_var("SELECT id FROM {$wpdb->prefix}mcpelee_ssg_events ORDER BY id DESC LIMIT 1 OFFSET 19999");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        if ($cutoff) { $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}mcpelee_ssg_events WHERE id < %d", $cutoff)); }
    }
    public static function blocked_page_path() {
        return wp_parse_url(plugins_url('assets/blocked.html', MCPELEE_SSG_PLUGIN_FILE), PHP_URL_PATH);
    }
    public static function redirect() {
        header('Cache-Control: private, no-store');
        header('Location: ' . self::blocked_page_path(), true, 302);
        exit;
    }
    public static function server_country($s) {
        $env = MCPELEE_SSG_Network::country_env($s['country_env']);
        $code = isset($_SERVER[$env]) && is_string($_SERVER[$env]) ? sanitize_text_field(wp_unslash($_SERVER[$env])) : '';
        if (!$code && isset($_SERVER['REDIRECT_' . $env]) && is_string($_SERVER['REDIRECT_' . $env])) { $code = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_' . $env])); }
        return is_string($code) && preg_match('/^[A-Z]{2}$/D', $code) ? $code : '';
    }
    public static function protect() {
        if (PHP_SAPI === 'cli' || wp_doing_cron() || ((defined('MCPELEE_SSG_EMERGENCY_DISABLE') && MCPELEE_SSG_EMERGENCY_DISABLE) || (defined('SSG_EMERGENCY_DISABLE') && SSG_EMERGENCY_DISABLE))) { return; }
        $s = self::settings(); $ip = self::ip();
        if (!MCPELEE_SSG_Network::matches($ip, $s['allowed']) && (MCPELEE_SSG_Network::policy_blocks($ip, self::server_country($s), $s) || ($s['login_limit'] && self::login_locked($ip)))) { self::redirect(); }
        if ($s['headers'] && !headers_sent()) {
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: strict-origin-when-cross-origin');
        }
        if ($s['xmlrpc'] && defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            self::log('xmlrpc_blocked', 'XML-RPC 요청 차단');
            status_header(403); nocache_headers(); exit('Access restricted');
        }
    }
    public static function authenticate($user, $username, $password) {
        if ((defined('MCPELEE_SSG_EMERGENCY_DISABLE') && MCPELEE_SSG_EMERGENCY_DISABLE) || (defined('SSG_EMERGENCY_DISABLE') && SSG_EMERGENCY_DISABLE)) { return $user; }
        $s = self::settings(); $ip = self::ip();
        if ($s['login_limit'] && !MCPELEE_SSG_Network::matches($ip, $s['allowed']) && self::login_locked($ip)) {
            return new WP_Error('mcpelee_ssg_locked', '로그인 시도가 일시적으로 제한되었습니다. 15분 후 다시 시도해 주세요.');
        }
        return $user;
    }
    public static function login_locked($ip) { return get_transient('mcpelee_ssg_lock_' . md5($ip)) || (get_option('mcpelee_ssg_prefix_migrated') && get_transient('ssg_lock_' . md5($ip))); }
    public static function login_failed() {
        self::log('login_failed', '인증 실패 (계정명·비밀번호 미기록)');
        $s = self::settings(); $ip = self::ip();
        if (!$s['login_limit'] || !$ip || MCPELEE_SSG_Network::matches($ip, $s['allowed'])) { return; }
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}mcpelee_ssg_events WHERE kind = 'login_failed' AND ip = %s AND created_at >= %s", $ip, gmdate('Y-m-d H:i:s', time() - 900)));
        if ($count >= 10 && !self::login_locked($ip)) {
            set_transient('mcpelee_ssg_lock_' . md5($ip), 1, 900);
            self::log('login_lock', '15분 동안 로그인 10회 이상 실패: 15분 임시 차단 (PHP 단계)');
        }
    }
    public static function access_log() {
        if (PHP_SAPI === 'cli' || wp_doing_cron() || !self::settings()['access_log']) { return; }
        $path = explode('?', sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '')), 2)[0];
        self::log('access', sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'] ?? '')) . ' ' . sanitize_text_field($path) . ' [' . (http_response_code() ?: 200) . ']');
    }
    public static function save_apache($s) {
        if (is_multisite()) { throw new RuntimeException('멀티사이트는 서버 관리자가 규칙을 별도로 적용해야 합니다.'); }
        $block = MCPELEE_SSG_Network::apache($s['blocked'], $s['allowed'], self::blocked_page_path(), $s);
        self::write_apache($block);
    }
    private static function write_apache($block) {
        // This installation's ABSPATH is the rewrite root. Custom subdirectory routing requires review.
        $file = ABSPATH . '.htaccess';
        if (is_link($file)) { throw new RuntimeException('.htaccess 심볼릭 링크는 자동 수정하지 않습니다.'); }
        if ($block === '' && !file_exists($file)) { delete_option('mcpelee_ssg_apache_hash'); return; }
        // A local file lock must protect this critical config across PHP workers; WP_Filesystem has no flock API.
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Required for advisory flock on the shared rules file.
        $lock = fopen(ABSPATH . '.mcpelee-ssg-htaccess.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX)) { throw new RuntimeException('.htaccess 잠금을 얻지 못했습니다.'); }
        try {
            if (!class_exists('WP_Filesystem_Direct')) {
                require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
                require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
            }
            $fs = new WP_Filesystem_Direct(null);
            $old = file_exists($file) ? $fs->get_contents($file) : '';
            if ($old === false) { throw new RuntimeException('.htaccess 읽기 실패'); }
            $new = MCPELEE_SSG_Network::merge($old, $block);
            if ($new === $old) { return; }
            // Backup in the database, never expose an .htaccess backup over HTTP.
            update_option('mcpelee_ssg_htaccess_backup', array('content' => $old, 'time' => gmdate('c')), false);
            $tmp = tempnam(ABSPATH, '.mcpelee-ssg-');
            if (!$tmp) { throw new RuntimeException('임시 파일 생성 실패'); }
            try {
                if (!$fs->put_contents($tmp, $new, 0600) || $fs->get_contents($tmp) !== $new || !$fs->chmod($tmp, file_exists($file) ? (fileperms($file) & 0777) : 0644)) { throw new RuntimeException('.htaccess 쓰기 실패'); }
                if ((file_exists($file) ? file_get_contents($file) : '') !== $old) { throw new RuntimeException('.htaccess가 다른 작업에서 변경되었습니다. 다시 시도해 주세요.'); }
                // WP_Filesystem_Direct::move(overwrite=true) deletes the live file first and may copy non-atomically.
                // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Same-filesystem atomic replacement preserves live protection if the operation fails.
                if (!rename($tmp, $file)) { throw new RuntimeException('.htaccess 교체 실패'); }
            } finally { if (file_exists($tmp)) { wp_delete_file($tmp); } }
            if ($block === '') { delete_option('mcpelee_ssg_apache_hash'); }
            else { update_option('mcpelee_ssg_apache_hash', hash('sha256', $block), false); }
        } finally {
            flock($lock, LOCK_UN);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the native flock handle.
            fclose($lock);
        }
    }
    public static function action() {
        if (!current_user_can('manage_options')) { wp_die('권한이 없습니다.', '', array('response' => 403)); }
        check_admin_referer('mcpelee_ssg_action');
        try {
            $op = sanitize_key(wp_unslash($_POST['operation'] ?? ''));
            if (in_array($op, array('save_ip', 'save_security', 'save_logging', 'save_scanner'), true)) {
                $s = self::updated_settings(self::settings(), $op, wp_unslash($_POST));
                if ($op === 'save_ip') {
                    if (MCPELEE_SSG_Network::matches(self::ip(), $s['blocked']) && !MCPELEE_SSG_Network::matches(self::ip(), $s['allowed'])) { throw new RuntimeException('현재 관리자 IP가 차단 범위에 포함됩니다. 허용 목록에 현재 IP를 먼저 추가하세요.'); }
                    if ($s['country_enabled'] && $s['country_blocked'] && !MCPELEE_SSG_Network::matches(self::ip(), $s['allowed'])) { throw new RuntimeException('국가 차단을 켜려면 현재 관리자 IP를 IP 허용 목록에 먼저 추가하세요. 국가 판별 오류로 관리자가 잠기는 것을 방지합니다.'); }
                    self::save_apache($s);
                }
                update_option('mcpelee_ssg_settings', $s, false);
                self::log('settings', '관리자 #' . get_current_user_id() . ': ' . $op . ' 설정 저장');
                $message = $op === 'save_ip' ? 'IP 정책을 저장하고 서버 규칙에 반영했습니다. 실제 서버 적용 여부를 확인하세요.' : '설정을 저장했습니다.';
            } elseif ($op === 'scan') {
                MCPELEE_SSG_Scanner::start(); MCPELEE_SSG_Scanner::step(); $message = '파일 검사를 진행했습니다. 완료 전까지 계속 버튼으로 진행할 수 있습니다.';
            } elseif ($op === 'step') {
                MCPELEE_SSG_Scanner::step(); $message = '파일 검사 한 묶음을 처리했습니다.';
            } elseif ($op === 'unlock') {
                $ip = MCPELEE_SSG_Network::normalize(sanitize_text_field(wp_unslash($_POST['unlock_ip'] ?? '')));
                if (strpos($ip, '/') !== false) { throw new RuntimeException('단일 IP를 입력하세요.'); }
                delete_transient('mcpelee_ssg_lock_' . md5($ip));
                delete_transient('ssg_lock_' . md5($ip));
                global $wpdb;
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}mcpelee_ssg_events WHERE kind='login_failed' AND ip=%s", $ip));
                self::log('unlock', '임시 차단 해제 및 실패 카운터 초기화: ' . $ip); $message = '임시 차단을 해제했습니다.';
            } else { throw new RuntimeException('알 수 없는 작업입니다.'); }
            set_transient('mcpelee_ssg_notice_' . get_current_user_id(), array('ok' => true, 'text' => $message), 60);
        } catch (Throwable $e) { set_transient('mcpelee_ssg_notice_' . get_current_user_id(), array('ok' => false, 'text' => $e->getMessage()), 60); }
        $tab = sanitize_key(wp_unslash($_POST['return_tab'] ?? 'overview'));
        if (!in_array($tab, array('overview', 'ip', 'security', 'files', 'logs'), true)) { $tab = 'overview'; }
        wp_safe_redirect(add_query_arg('tab', $tab, admin_url('options-general.php?page=site-security-guard'))); exit;
    }
    public static function updated_settings($s, $op, $input) {
        $groups = array('save_security' => array('headers', 'login_limit', 'xmlrpc', 'hide_users'), 'save_logging' => array('access_log', 'country_lookup'), 'save_scanner' => array('daily_scan'));
        if ($op === 'save_ip') {
            $s['blocked'] = MCPELEE_SSG_Network::parse($input['blocked'] ?? '');
            $s['allowed'] = MCPELEE_SSG_Network::parse($input['allowed'] ?? '');
            $s['country_enabled'] = empty($input['country_enabled']) ? 0 : 1;
            $s['country_blocked'] = MCPELEE_SSG_Network::country_codes($input['country_blocked'] ?? array());
            $s['country_allowed'] = MCPELEE_SSG_Network::country_codes($input['country_allowed'] ?? array());
            $s['country_env'] = MCPELEE_SSG_Network::country_env($input['country_env'] ?? 'MM_COUNTRY_CODE');
        } elseif (isset($groups[$op])) {
            foreach ($groups[$op] as $key) { $s[$key] = empty($input[$key]) ? 0 : 1; }
            if ($op === 'save_logging') { $s['retention'] = max(1, min(90, (int)($input['retention'] ?? 7))); }
        } else { throw new InvalidArgumentException('알 수 없는 설정입니다.'); }
        return $s;
    }
    public static function page() {
        if (!current_user_can('manage_options')) { return; }
        require_once __DIR__ . '/class-mcpelee-ssg-admin.php';
        MCPELEE_SSG_Admin::render();
    }
}

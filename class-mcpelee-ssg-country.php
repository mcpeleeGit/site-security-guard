<?php
if (!defined('ABSPATH')) { exit; }
final class MCPELEE_SSG_Country {
    public static function initial($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return array('name' => '—'); }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return array('name' => '내부/예약 IP'); }
        if (MCPELEE_SSG_Network::matches($ip, array('100.64.0.0/10', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '2001:db8::/32', 'ff00::/8'))) { return array('name' => '내부/예약 IP'); }
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $row = $wpdb->get_row($wpdb->prepare("SELECT code,name FROM {$wpdb->prefix}mcpelee_ssg_countries WHERE ip=%s AND expires>%s", $ip, gmdate('Y-m-d H:i:s')), ARRAY_A);
        if ($row) { return $row; }
        $cached = get_transient('mcpelee_ssg_country_' . md5(inet_ntop(inet_pton($ip))));
        if (is_array($cached)) {
            $expiry = (int)get_option('_transient_timeout_mcpelee_ssg_country_' . md5(inet_ntop(inet_pton($ip))), time() + HOUR_IN_SECONDS);
            self::store($ip, $cached, max(1, min(30 * DAY_IN_SECONDS, $expiry - time())));
            return $cached;
        }
        return array('name' => MCPELEE_SSG_Guard::settings()['country_lookup'] ? '조회 대기' : '조회 꺼짐', 'pending' => true);
    }
    public static function lookup($ip) {
        $initial = self::initial($ip);
        if (empty($initial['pending']) || !MCPELEE_SSG_Guard::settings()['country_lookup']) { return $initial; }
        if (get_transient('mcpelee_ssg_country_cooldown')) { return array('name' => '조회 제한'); }
        $budget = get_option('mcpelee_ssg_country_budget', array());
        if (($budget['day'] ?? '') !== gmdate('Y-m-d')) { $budget = array('day' => gmdate('Y-m-d'), 'count' => 0); }
        if ($budget['count'] >= 900) { return array('name' => '일일 조회 한도'); }
        $budget['count']++; update_option('mcpelee_ssg_country_budget', $budget, false);
        $response = wp_safe_remote_get('https://ipwho.is/' . rawurlencode($ip) . '?fields=success,country,country_code', array('timeout' => 2, 'redirection' => 0, 'limit_response_size' => 4096, 'cookies' => array()));
        $result = array('name' => '확인 불가'); $ttl = HOUR_IN_SECONDS;
        if (!is_wp_error($response)) {
            $status = wp_remote_retrieve_response_code($response);
            if ($status === 429) { set_transient('mcpelee_ssg_country_cooldown', 1, DAY_IN_SECONDS); }
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if ($status === 200 && is_array($data) && ($data['success'] ?? false) === true && is_string($data['country_code'] ?? null) && preg_match('/^[A-Z]{2}$/D', $data['country_code']) && is_string($data['country'] ?? null)) {
                $code = $data['country_code'];
                $name = class_exists('Locale') ? Locale::getDisplayRegion('und_' . $code, 'ko') : sanitize_text_field($data['country']);
                $result = array('code' => $code, 'name' => mb_substr($name, 0, 80)); $ttl = 30 * DAY_IN_SECONDS;
            }
        }
        self::store($ip, $result, $ttl);
        return $result;
    }
    public static function store($ip, $result, $ttl) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $wpdb->replace(MCPELEE_SSG_Guard::table('countries'), array('ip' => $ip, 'code' => $result['code'] ?? '', 'name' => $result['name'], 'expires' => gmdate('Y-m-d H:i:s', time() + $ttl)));
    }
    public static function ajax() {
        if (!current_user_can('manage_options')) { wp_send_json_error(null, 403); }
        check_ajax_referer('mcpelee_ssg_country');
        if (!MCPELEE_SSG_Guard::settings()['country_lookup']) { wp_send_json_error(null, 403); }
        $ips = isset($_POST['ips']) && is_array($_POST['ips']) ? map_deep(wp_unslash($_POST['ips']), 'sanitize_text_field') : array();
        if (!is_array($ips) || count($ips) > 5) { wp_send_json_error(null, 400); }
        // Serialize admin batches across tabs to avoid concurrent quota/cache misses.
        global $wpdb;
        $lock = 'mcpelee_ssg_geo_' . md5(ABSPATH . $wpdb->prefix);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        if ((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== 1) { wp_send_json_error(null, 429); }
        $result = array();
        try {
            global $wpdb;
            foreach (array_unique(array_filter($ips, 'is_string')) as $ip) {
                if (!filter_var($ip, FILTER_VALIDATE_IP)) { continue; }
                // Only recorded IPs may be looked up, not arbitrary user-supplied URLs/addresses.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}mcpelee_ssg_events WHERE ip=%s LIMIT 1", $ip));
                if ($exists) { $result[$ip] = self::lookup($ip); }
            }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        } finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
        wp_send_json_success($result);
    }
}

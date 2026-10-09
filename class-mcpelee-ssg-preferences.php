<?php
if (!defined('ABSPATH')) { exit; }
final class MCPELEE_SSG_Preferences {
    public static function excluded() {
        $value = get_user_option('mcpelee_ssg_exclude_self', get_current_user_id());
        if ($value === false && get_option('mcpelee_ssg_prefix_migrated')) {
            $value = get_user_option('ssg_exclude_self', get_current_user_id());
            if ($value !== false) { self::save($value); }
        }
        return $value === '1';
    }
    public static function save($value) { update_user_option(get_current_user_id(), 'mcpelee_ssg_exclude_self', $value === '1' ? '1' : '0', false); }
    public static function from_form() {
        if (!current_user_can('manage_options') || sanitize_text_field(wp_unslash($_GET['page'] ?? '')) !== 'site-security-guard' || sanitize_text_field(wp_unslash($_GET['tab'] ?? '')) !== 'logs') { return; }
        if (isset($_GET['mcpelee_ssg_pref_nonce']) && is_string($_GET['mcpelee_ssg_pref_nonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['mcpelee_ssg_pref_nonce'])), 'mcpelee_ssg_preferences') && isset($_GET['exclude_self']) && is_string($_GET['exclude_self'])) { self::save(sanitize_text_field(wp_unslash($_GET['exclude_self']))); }
    }
    public static function ajax() {
        if (!current_user_can('manage_options')) { wp_send_json_error(null, 403); }
        check_ajax_referer('mcpelee_ssg_preferences');
        self::save(isset($_POST['exclude_self']) && sanitize_text_field(wp_unslash($_POST['exclude_self'])) === '1' ? '1' : '0');
        wp_send_json_success();
    }
}

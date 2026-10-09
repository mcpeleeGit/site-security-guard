<?php
if (!defined('ABSPATH')) { exit; }
/** One-time migration of the plugin's development-era identifiers. */
final class MCPELEE_SSG_Migration {
    public static function run() {
        if (get_option('mcpelee_ssg_prefix_migrated')) { return; }
        // Only installations with our legacy schema marker are migrated.
        if (!in_array(get_option('ssg_version'), array('1', '2'), true)) { return; }
        global $wpdb;
        $lock = 'mcpelee_ssg_migration_' . md5(ABSPATH . $wpdb->prefix);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        if ((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 10)', $lock)) !== 1) { wp_die('Site Security Guard 데이터 이전 잠금을 얻지 못했습니다. 잠시 후 다시 시도하세요.'); }
        try {
            if (get_option('mcpelee_ssg_prefix_migrated')) { return; }
            $renames = array();
            foreach (array('events','files','countries') as $suffix) {
                $old = $wpdb->prefix . 'ssg_' . $suffix; $new = MCPELEE_SSG_Guard::table($suffix);
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                $has_old = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($old))) === $old;
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                $has_new = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($new))) === $new;
                if ($has_old && $has_new) { throw new RuntimeException('이전/신규 보안 테이블이 모두 존재합니다. 데이터를 보존하기 위해 이전을 중단했습니다.'); }
                if ($has_old) { $renames[] = $suffix; }
            }
            // Fixed identifiers only. A retry resumes any already-renamed table after partial failure.
            foreach ($renames as $suffix) {
                switch ($suffix) {
                    case 'events':
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                        $renamed = $wpdb->query("RENAME TABLE {$wpdb->prefix}ssg_events TO {$wpdb->prefix}mcpelee_ssg_events");
                        break;
                    case 'files':
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                        $renamed = $wpdb->query("RENAME TABLE {$wpdb->prefix}ssg_files TO {$wpdb->prefix}mcpelee_ssg_files");
                        break;
                    case 'countries':
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                        $renamed = $wpdb->query("RENAME TABLE {$wpdb->prefix}ssg_countries TO {$wpdb->prefix}mcpelee_ssg_countries");
                        break;
                }
                if ($renamed === false) { throw new RuntimeException('보안 테이블 이름 변경 권한이 필요합니다.'); }
            }
            foreach (array('settings','version','scan_state','scan_last','baseline_ready','apache_hash','htaccess_backup','country_budget','exclude_self') as $suffix) {
                $value = get_option('ssg_' . $suffix, null);
                if ($value !== null) { add_option('mcpelee_ssg_' . $suffix, $value, '', false); }
            }
            // Copy database-backed transient values together with their original expiry.
            foreach (array('ssg_lock_', 'ssg_country_', 'ssg_notice_') as $prefix) {
                foreach (array('_transient_', '_transient_timeout_') as $type) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                    $rows = $wpdb->get_results($wpdb->prepare("SELECT option_name, option_value FROM $wpdb->options WHERE option_name LIKE %s", $wpdb->esc_like($type . $prefix) . '%'));
                    foreach ($rows as $row) { add_option($type . 'mcpelee_' . substr($row->option_name, strlen($type)), maybe_unserialize($row->option_value), '', false); }
                }
            }
            foreach (array('ssg_cleanup','ssg_daily_scan','ssg_scan_step') as $hook) { wp_clear_scheduled_hook($hook); }
            MCPELEE_SSG_Guard::schedule();
            update_option('mcpelee_ssg_prefix_migrated', 1, false);
        } catch (Throwable $e) {
            wp_die(esc_html('Site Security Guard: ' . $e->getMessage()));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        } finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
    }
}

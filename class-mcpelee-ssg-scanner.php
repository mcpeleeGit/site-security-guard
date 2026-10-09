<?php
if (!defined('ABSPATH')) { exit; }
final class MCPELEE_SSG_Scanner {
    private static function lock() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        return (int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', 'mcpelee_ssg_scan_' . md5(ABSPATH . $wpdb->prefix))) === 1;
    }
    private static function unlock() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', 'mcpelee_ssg_scan_' . md5(ABSPATH . $wpdb->prefix)));
    }
    public static function start() {
        if (!self::lock()) { return; }
        try {
            if (get_option('mcpelee_ssg_scan_state')) { return; }
            update_option('mcpelee_ssg_scan_state', array('id' => wp_generate_uuid4(), 'started' => gmdate('c'), 'queue' => array(''), 'pending' => array(), 'count' => 0, 'skipped' => 0, 'incomplete' => false, 'baseline' => !get_option('mcpelee_ssg_baseline_ready')), false);
            if (!wp_next_scheduled('mcpelee_ssg_scan_step')) { wp_schedule_single_event(time() + 10, 'mcpelee_ssg_scan_step'); }
        } finally { self::unlock(); }
    }
    private static function warning(&$state, $path, $why) {
        $state['skipped']++;
        MCPELEE_SSG_Guard::log('scan_warning', $path . ': ' . $why);
    }
    public static function step() {
        if (!self::lock()) { return; }
        try { self::process(); } finally { self::unlock(); }
    }
    private static function process() {
        global $wpdb;
        $state = get_option('mcpelee_ssg_scan_state');
        if (!$state) { return; }
        $table = MCPELEE_SSG_Guard::table('files'); $start = microtime(true); $processed = 0; $bytes = 0;
        // Bounded batches; the queue contains paths only, never file contents.
        while ($processed < 150 && microtime(true) - $start < 3 && $bytes < 16 * 1024 * 1024) {
            if (!$state['pending']) {
                if (!$state['queue']) { break; }
                $dir = array_shift($state['queue']);
                if (is_link(ABSPATH . $dir)) { $state['incomplete'] = true; self::warning($state, $dir, '검사 도중 심볼릭 링크로 변경됨'); continue; }
                $entries = @scandir(ABSPATH . $dir);
                if ($entries === false) { $state['incomplete'] = true; self::warning($state, $dir, '디렉터리 읽기 실패; 이번 검사의 삭제 판정 생략'); continue; }
                foreach ($entries as $entry) { if ($entry !== '.' && $entry !== '..') { $state['pending'][] = $dir . $entry; } }
                $processed++;
                continue;
            }
            $relative = array_shift($state['pending']); $file = ABSPATH . $relative; $processed++;
            if (is_link($file)) { $state['incomplete'] = true; self::warning($state, $relative, '심볼릭 링크 제외'); continue; }
            if (is_dir($file)) {
                if (preg_match('~(^|/)(\.git|node_modules|cache|upgrade|upgrade-temp-backup)(/|$)~', $relative)) { continue; }
                $state['queue'][] = $relative . '/'; continue;
            }
            if (str_starts_with($relative, '.mcpelee-ssg-')) { continue; }
            if (str_starts_with($relative, 'wp-content/uploads/') && !preg_match('/\.(php\d*|phtml|phar|cgi|pl|py|sh|js|html?|htaccess)$/i', $relative)) { continue; }
            $state['count']++;
            $key = hash('sha256', $relative);
            // Mark seen even if unreadable/oversized so it is never falsely reported as deleted.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
            if ($wpdb->query($wpdb->prepare("UPDATE {$wpdb->prefix}mcpelee_ssg_files SET seen=%s WHERE path_key=%s", $state['id'], $key)) === false) { $state['incomplete'] = true; }
            $size = @filesize($file);
            if ($size === false || $size > 16 * 1024 * 1024) { self::warning($state, $relative, '크기 확인 실패 또는 16MB 초과'); continue; }
            $digest = @hash_file('sha256', $file); $bytes += $size;
            if ($digest === false) { self::warning($state, $relative, '파일 읽기 실패'); continue; }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
            $old = $wpdb->get_var($wpdb->prepare("SELECT digest FROM {$wpdb->prefix}mcpelee_ssg_files WHERE path_key=%s", $key));
            if ($wpdb->last_error) { $state['incomplete'] = true; self::warning($state, $relative, '기준값 DB 읽기 실패'); continue; }
            if (!$state['baseline'] && $old !== $digest) {
                MCPELEE_SSG_Guard::log($old ? 'file_changed' : 'file_added', $relative . ' | SHA256 ' . ($old ?: '(없음)') . ' → ' . $digest);
            }
            if (!$old && str_starts_with($relative, 'wp-content/uploads/') && preg_match('/\.(php\d*|phtml|phar|cgi)$/i', $relative)) { MCPELEE_SSG_Guard::log('scan_warning', '업로드 폴더의 실행 가능 파일 확인 필요: ' . $relative); }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
            if ($wpdb->replace($table, array('path_key' => $key, 'path' => $relative, 'digest' => $digest, 'seen' => $state['id'])) === false) { $state['incomplete'] = true; self::warning($state, $relative, '기준값 DB 저장 실패'); }
        }
        if (!$state['pending'] && !$state['queue']) {
            if (!$state['baseline'] && !$state['incomplete']) {
                // Deletions are also processed in bounded batches.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                $deleted = $wpdb->get_results($wpdb->prepare("SELECT path_key,path FROM {$wpdb->prefix}mcpelee_ssg_files WHERE seen <> %s LIMIT 150", $state['id']));
                if ($wpdb->last_error) { $state['incomplete'] = true; }
                foreach ($deleted as $row) {
                    MCPELEE_SSG_Guard::log('file_deleted', $row->path);
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
                    if ($wpdb->delete($table, array('path_key' => $row->path_key)) === false) { $state['incomplete'] = true; }
                }
                if (count($deleted) === 150 && !$state['incomplete']) { self::persist($state); return; }
            }
            $last = array('finished' => gmdate('c'), 'count' => $state['count'], 'skipped' => $state['skipped']);
            update_option('mcpelee_ssg_scan_last', $last, false);
            if (!$state['incomplete']) { update_option('mcpelee_ssg_baseline_ready', 1, false); }
            delete_option('mcpelee_ssg_scan_state'); wp_clear_scheduled_hook('mcpelee_ssg_scan_step');
            MCPELEE_SSG_Guard::log('scan_complete', ($state['baseline'] ? '최초 기준값 검사' : '변경 검사') . ': ' . $state['count'] . '개, 제외/오류 ' . $state['skipped'] . '개' . ($state['incomplete'] ? '; 일부 미확인, 삭제 판정 생략' : ''));
        } else { self::persist($state); }
    }
    private static function persist($state) {
        update_option('mcpelee_ssg_scan_state', $state, false);
        if (!wp_next_scheduled('mcpelee_ssg_scan_step')) { wp_schedule_single_event(time() + 10, 'mcpelee_ssg_scan_step'); }
    }
}

<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
/** Run from this WordPress root: php wp-content/plugins/site-security-guard/tests/mcpelee-ssg-wordpress.php
 * Uses disposable DB tables and fixture files. Never changes production security settings.
 */
require dirname(__DIR__, 4) . '/wp-load.php';
require_once dirname(__DIR__) . '/site-security-guard.php';
if (wp_using_ext_object_cache()) { throw new RuntimeException('Use a disposable WordPress instance without persistent object caching.'); }
$original_prefix = $wpdb->prefix; $original_options = $wpdb->options;
$test_prefix = $original_prefix . 'ssgtest_' . bin2hex(random_bytes(4)) . '_';
$fixture = 'wp-content/mcpelee-ssg-test-' . bin2hex(random_bytes(4));
$checks = 0;
function verify($ok, $message) { global $checks; $checks++; if (!$ok) { throw new RuntimeException($message); } }
function scan_fixture($fixture) {
    MCPELEE_SSG_Scanner::start();
    $s = get_option('mcpelee_ssg_scan_state'); $s['queue'] = array($fixture . '/'); update_option('mcpelee_ssg_scan_state', $s, false);
    for ($i = 0; $i < 20 && get_option('mcpelee_ssg_scan_state'); $i++) { MCPELEE_SSG_Scanner::step(); }
    verify(!get_option('mcpelee_ssg_scan_state'), 'Scan completes');
}
try {
    $wpdb->query("CREATE TABLE {$test_prefix}options LIKE $original_options");
    $wpdb->prefix = $test_prefix; $wpdb->options = $test_prefix . 'options'; wp_cache_flush();
    MCPELEE_SSG_Guard::install();
    verify(get_option('mcpelee_ssg_version') === MCPELEE_SSG_Guard::VERSION, 'Schema installed');
    $_SERVER['REMOTE_ADDR'] = '192.0.2.22'; $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1';
    verify(MCPELEE_SSG_Guard::ip() === '192.0.2.22', 'Does not trust X-Forwarded-For');
    for ($i = 0; $i < 9; $i++) { MCPELEE_SSG_Guard::login_failed(); }
    verify(!get_transient('mcpelee_ssg_lock_' . md5('192.0.2.22')), 'Nine failures allowed');
    MCPELEE_SSG_Guard::login_failed();
    verify((bool)get_transient('mcpelee_ssg_lock_' . md5('192.0.2.22')), 'Ten failures lock');
    verify(is_wp_error(MCPELEE_SSG_Guard::authenticate(null, 'test', 'unused')), 'Authentication rejects locked IP');
    $s = MCPELEE_SSG_Guard::settings(); $s['allowed'] = array('192.0.2.0/24'); update_option('mcpelee_ssg_settings', $s, false);
    verify(MCPELEE_SSG_Guard::authenticate(null, 'test', 'unused') === null, 'Allow overrides temporary lock');
    mkdir(ABSPATH . $fixture);
    file_put_contents(ABSPATH . $fixture . '/keep.php', '<?php // baseline');
    file_put_contents(ABSPATH . $fixture . '/delete.php', '<?php // deleted later');
    scan_fixture($fixture);
    verify((int)$wpdb->get_var('SELECT COUNT(*) FROM ' . MCPELEE_SSG_Guard::table('files')) === 2, 'Baseline has two files');
    verify((int)$wpdb->get_var("SELECT COUNT(*) FROM " . MCPELEE_SSG_Guard::table('events') . " WHERE kind='file_added'") === 0, 'Initial scan not an incident');
    file_put_contents(ABSPATH . $fixture . '/keep.php', '<?php // changed');
    unlink(ABSPATH . $fixture . '/delete.php');
    file_put_contents(ABSPATH . $fixture . '/add.php', '<?php // added');
    scan_fixture($fixture);
    foreach (array('file_changed', 'file_added', 'file_deleted') as $kind) {
        verify((int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM ' . MCPELEE_SSG_Guard::table('events') . ' WHERE kind=%s', $kind)) === 1, $kind . ' detected');
    }
    $wpdb->insert(MCPELEE_SSG_Guard::table('events'), array('created_at' => '2000-01-01 00:00:00', 'kind' => 'old', 'ip' => '', 'detail' => 'expired'));
    MCPELEE_SSG_Guard::cleanup();
    verify((int)$wpdb->get_var("SELECT COUNT(*) FROM " . MCPELEE_SSG_Guard::table('events') . " WHERE kind='old'") === 0, 'Expired events pruned');
    // Rendering uses an existing admin identity only within this CLI process.
    $admin = get_users(array('role' => 'administrator', 'number' => 1, 'fields' => 'ID'));
    if ($admin) {
        wp_set_current_user($admin[0]);
        MCPELEE_SSG_Guard::log('access', '<script>alert(1)</script>');
        $_GET['tab'] = 'logs';
        ob_start(); MCPELEE_SSG_Guard::page(); $html = ob_get_clean();
        verify(str_contains($html, 'Site Security Guard'), 'Admin page rendered');
        verify(!str_contains($html, '<script>alert(1)</script>') && str_contains($html, '&lt;script&gt;'), 'Logs escaped');
        verify(str_contains($html, '_wpnonce'), 'Mutation forms have CSRF nonce');
    }
    add_filter('wp_die_handler', function () { return function () { throw new RuntimeException('access_denied'); }; });
    wp_set_current_user(0);
    try { MCPELEE_SSG_Guard::action(); verify(false, 'Guest mutation accepted'); } catch (RuntimeException $e) { verify($e->getMessage() === 'access_denied', 'Guest mutation denied'); }
    if ($admin) {
        wp_set_current_user($admin[0]);
        $_REQUEST['_wpnonce'] = 'invalid';
        try { MCPELEE_SSG_Guard::action(); verify(false, 'Invalid nonce accepted'); } catch (RuntimeException $e) { verify($e->getMessage() === 'access_denied', 'Invalid nonce denied'); }
    }
    $settings = array_merge(MCPELEE_SSG_Guard::defaults(), array('blocked' => array('192.0.2.1'), 'daily_scan' => 1, 'access_log' => 1, 'retention' => 30));
    $changed = MCPELEE_SSG_Guard::updated_settings($settings, 'save_security', array('xmlrpc' => 1));
    verify($changed['blocked'] === $settings['blocked'] && $changed['daily_scan'] === 1 && $changed['access_log'] === 1 && $changed['retention'] === 30, 'Security tab preserves other settings');
    verify($changed['headers'] === 0 && $changed['xmlrpc'] === 1, 'Security checkbox updates');
    $changed = MCPELEE_SSG_Guard::updated_settings($settings, 'save_ip', array('blocked' => '198.51.100.1', 'allowed' => '192.0.2.2'));
    verify($changed['headers'] === $settings['headers'] && $changed['retention'] === 30 && $changed['daily_scan'] === 1, 'IP tab preserves other settings');
    $changed = MCPELEE_SSG_Guard::updated_settings($settings, 'save_logging', array('retention' => 999));
    verify($changed['access_log'] === 0 && $changed['retention'] === 90 && $changed['blocked'] === $settings['blocked'], 'Log settings bounded and isolated');
    $changed = MCPELEE_SSG_Guard::updated_settings($settings, 'save_scanner', array());
    verify($changed['daily_scan'] === 0 && $changed['access_log'] === 1, 'Scanner settings isolated');
    if ($admin) {
        foreach (array('overview', 'ip', 'security', 'files', 'logs', 'invalid') as $tab) {
            $_GET['tab'] = $tab;
            ob_start(); MCPELEE_SSG_Guard::page(); $html = ob_get_clean();
            verify(substr_count($html, 'aria-current="page"') === 1, 'Exactly one active tab: ' . $tab);
            verify($tab === 'ip' ? str_contains($html, 'name="blocked"') : !str_contains($html, 'name="blocked"'), 'IP form only in IP tab: ' . $tab);
        }
    }
    $geo = MCPELEE_SSG_Guard::settings(); $geo['country_lookup'] = 1; update_option('mcpelee_ssg_settings', $geo, false);
    $calls = 0;
    $mock = function ($pre, $args, $url) use (&$calls) {
        $calls++;
        verify(str_starts_with($url, 'https://ipwho.is/'), 'Country lookup uses fixed HTTPS provider');
        return array('response' => array('code' => 200), 'body' => '{"success":true,"country":"South Korea","country_code":"KR"}');
    };
    add_filter('pre_http_request', $mock, 10, 3);
    foreach (array('127.0.0.1', '10.1.2.3', '::1', '192.0.2.1', '100.64.1.1', '2001:db8::1') as $ip) {
        verify(MCPELEE_SSG_Country::lookup($ip)['name'] === '내부/예약 IP', 'No geolocation for reserved IP ' . $ip);
    }
    verify($calls === 0, 'Private IPs never transmitted');
    $country = MCPELEE_SSG_Country::lookup('8.8.8.8');
    verify($country['code'] === 'KR', 'Country response parsed');
    verify(MCPELEE_SSG_Country::lookup('8.8.8.8') === $country && $calls === 1, 'Country cache reused');
    $geo['country_lookup'] = 0; update_option('mcpelee_ssg_settings', $geo, false);
    verify(MCPELEE_SSG_Country::lookup('1.1.1.1')['name'] === '조회 꺼짐' && $calls === 1, 'Disabled lookup never transmits');
    remove_filter('pre_http_request', $mock, 10);
    $geo['country_lookup'] = 1; update_option('mcpelee_ssg_settings', $geo, false);
    $fail_calls = 0;
    $fail = function () use (&$fail_calls) { $fail_calls++; return new WP_Error('timeout', 'timeout'); };
    add_filter('pre_http_request', $fail);
    verify(MCPELEE_SSG_Country::lookup('1.1.1.1')['name'] === '확인 불가', 'Timeout handled');
    MCPELEE_SSG_Country::lookup('1.1.1.1'); verify($fail_calls === 1, 'Failed lookups cached');
    remove_filter('pre_http_request', $fail);
    $limited = function () { return array('response' => array('code' => 429), 'body' => ''); };
    add_filter('pre_http_request', $limited);
    MCPELEE_SSG_Country::lookup('9.9.9.9');
    verify(MCPELEE_SSG_Country::lookup('8.8.4.4')['name'] === '조회 제한', 'Provider cooldown honored');
    remove_filter('pre_http_request', $limited);
    require_once dirname(__DIR__) . '/class-mcpelee-ssg-log-query.php';
    for ($i=0; $i<60; $i++) {
        $wpdb->insert(MCPELEE_SSG_Guard::table('events'), array('created_at'=>'2026-01-01 00:00:00','kind'=>$i%2 ? 'login_failed':'access','ip'=>$i%2 ? '1.1.1.1':'8.8.8.8','detail'=>'query_fixture'));
    }
    $_SERVER['REMOTE_ADDR']='8.8.8.8';
    $query=MCPELEE_SSG_Log_Query::state(array('detail'=>'query_fixture','sort'=>'created_at','order'=>'asc'));
    $first=MCPELEE_SSG_Log_Query::rows($query);
    verify(count($first)===51, 'Pagination fetches lookahead over whole dataset');
    $query['log_page']=2; $next=MCPELEE_SSG_Log_Query::rows($query);
    verify(count($next)===10 && $next[0]->id===$first[50]->id, 'Stable tied timestamp pagination');
    $query['log_page']=1; $query['exclude_self']='1';
    verify(count(MCPELEE_SSG_Log_Query::rows($query))===30, 'Current IP excluded from entire result');
    $query['exclude_self']=''; $query['ip']='1.1.1.1';
    verify(count(MCPELEE_SSG_Log_Query::rows($query))===30, 'Clicked IP filter');
    $query['kind']='access'; verify(count(MCPELEE_SSG_Log_Query::rows($query))===0, 'Filters intersect');
    $query['kind']=''; $query['ip']=''; $query['country']='KR';
    verify(count(MCPELEE_SSG_Log_Query::rows($query))===30, 'Country filter uses valid cached country');
    $query['country']=''; $query['sort']='ip';
    verify(MCPELEE_SSG_Log_Query::rows($query)[0]->ip==='1.1.1.1', 'IP ascending sort');
    $query['order']='desc'; verify(MCPELEE_SSG_Log_Query::rows($query)[0]->ip==='8.8.8.8', 'IP descending sort');
    $query['date']='2026-01-02'; verify(count(MCPELEE_SSG_Log_Query::rows($query))===0, 'Date filter');
    $unsafe=MCPELEE_SSG_Log_Query::state(array('sort'=>'id; DROP TABLE','order'=>'injection','ip'=>array('bad'),'date'=>'2026-02-31'));
    verify($unsafe['sort']==='created_at' && $unsafe['order']==='desc' && $unsafe['ip']==='' && $unsafe['date']==='', 'Untrusted sort and filter input constrained');
    foreach (array('created_at','kind','ip','country','detail') as $sort_key) {
        foreach (array('asc','desc') as $direction) {
            $sort_state = MCPELEE_SSG_Log_Query::state(array('detail'=>'query_fixture','sort'=>$sort_key,'order'=>$direction));
            $sorted = MCPELEE_SSG_Log_Query::rows($sort_state);
            verify(count($sorted) === 51 && !$wpdb->last_error, 'Prepared ordering ' . $sort_key . ' ' . $direction);
        }
    }
    $literal = "quote ' percent %s _ <script> 한국어";
    $wpdb->insert(MCPELEE_SSG_Guard::table('events'), array('created_at'=>'2026-01-01 00:00:00','kind'=>'access','ip'=>'8.8.8.8','detail'=>$literal));
    $exact = MCPELEE_SSG_Log_Query::rows(MCPELEE_SSG_Log_Query::state(array('detail'=>$literal)));
    verify(count($exact) === 1 && $exact[0]->detail === $literal, 'Quoted literal filters remain exact and safe');
    $before_events = (int)$wpdb->get_var('SELECT COUNT(*) FROM ' . MCPELEE_SSG_Guard::table('events'));
    $before_files = (int)$wpdb->get_var('SELECT COUNT(*) FROM ' . MCPELEE_SSG_Guard::table('files'));
    $renames = array();
    foreach (array('events','files','countries') as $suffix) { $renames[] = MCPELEE_SSG_Guard::table($suffix) . ' TO ' . $test_prefix . 'ssg_' . $suffix; }
    $wpdb->query('RENAME TABLE ' . implode(', ', $renames));
    delete_option('mcpelee_ssg_settings'); delete_option('mcpelee_ssg_version');
    update_option('ssg_version', '2', false);
    update_option('ssg_settings', array('retention'=>21), false);
    set_transient('ssg_lock_' . md5('8.8.4.4'), 1, 120);
    wp_schedule_single_event(time()+600, 'ssg_scan_step');
    MCPELEE_SSG_Migration::run();
    verify(MCPELEE_SSG_Guard::settings()['retention'] === 21, 'Legacy settings migrated');
    verify((int)$wpdb->get_var('SELECT COUNT(*) FROM ' . MCPELEE_SSG_Guard::table('events')) === $before_events, 'Migration preserves event rows');
    verify((int)$wpdb->get_var('SELECT COUNT(*) FROM ' . MCPELEE_SSG_Guard::table('files')) === $before_files, 'Migration preserves file baseline');
    verify((bool)get_transient('mcpelee_ssg_lock_' . md5('8.8.4.4')), 'Temporary locks migrated');
    verify(!wp_next_scheduled('ssg_scan_step') && wp_next_scheduled('mcpelee_ssg_cleanup'), 'Cron hooks migrated');
    MCPELEE_SSG_Migration::run();
    verify(MCPELEE_SSG_Guard::settings()['retention'] === 21, 'Migration is idempotent');
    echo "$checks WordPress integration checks passed\n";
} finally {
    foreach (array('events','files','countries') as $table) { $wpdb->query('DROP TABLE IF EXISTS ' . $test_prefix . 'mcpelee_ssg_' . $table); }
    $wpdb->query('DROP TABLE IF EXISTS ' . $test_prefix . 'options');
    $wpdb->prefix = $original_prefix; $wpdb->options = $original_options; wp_cache_flush();
    foreach (array('keep.php', 'delete.php', 'add.php') as $name) { if (file_exists(ABSPATH . $fixture . '/' . $name)) { unlink(ABSPATH . $fixture . '/' . $name); } }
    if (is_dir(ABSPATH . $fixture)) { rmdir(ABSPATH . $fixture); }
}

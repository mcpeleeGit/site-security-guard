<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$root = sys_get_temp_dir() . '/mcpelee-ssg-lifecycle-' . bin2hex(random_bytes(6)) . '/';
mkdir($root, 0700);
define('ABSPATH', $root);
define('MCPELEE_SSG_PLUGIN_FILE', dirname(__DIR__) . '/site-security-guard.php');
$options = array('mcpelee_ssg_version' => '2', 'mcpelee_ssg_settings' => array('blocked' => array('192.0.2.1')), 'mcpelee_ssg_baseline_ready' => 1);
$cron = array(); $checks = 0;
function get_option($key, $default = false) { global $options; return $options[$key] ?? $default; }
function update_option($key, $value, $autoload = false) { global $options; $options[$key] = $value; return true; }
function delete_option($key) { global $options; unset($options[$key]); }
function is_multisite() { return false; }
function wp_die($message) { throw new RuntimeException($message); }
function esc_html($text) { return htmlspecialchars($text); }
function plugins_url($path, $file) { return 'https://example.test/wp-content/plugins/site-security-guard/' . $path; }
function wp_parse_url($url, $component) { return parse_url($url, $component); }
function wp_next_scheduled($key) { global $cron; return isset($cron[$key]); }
function wp_schedule_event($time, $frequency, $key) { global $cron; $cron[$key] = $time; }
function wp_schedule_single_event($time, $key) { global $cron; $cron[$key] = $time; }
function wp_clear_scheduled_hook($key) { global $cron; unset($cron[$key]); }
function verify_lifecycle($ok, $why) { global $checks; $checks++; if (!$ok) { throw new RuntimeException($why); } }
// Load the real WordPress direct-filesystem implementation against the temporary root.
class WP_Error {}
function mbstring_binary_safe_encoding() {}
function reset_mbstring_encoding() {}
function wp_delete_file($path) { unlink($path); }
require dirname(__DIR__, 4) . '/wp-admin/includes/class-wp-filesystem-base.php';
require dirname(__DIR__, 4) . '/wp-admin/includes/class-wp-filesystem-direct.php';
require dirname(__DIR__) . '/class-mcpelee-ssg-network.php';
require dirname(__DIR__) . '/class-mcpelee-ssg-guard.php';
try {
    $original = "# BEGIN WordPress\nRewriteRule . /index.php [L]\n# END WordPress\n";
    $legacy = MCPELEE_SSG_Network::apache(array('192.0.2.1'), array(), '/wp-content/mu-plugins/site-security-guard/assets/blocked.html');
    file_put_contents($root . '.htaccess', $legacy . $original);
    MCPELEE_SSG_Guard::activate();
    $active = file_get_contents($root . '.htaccess');
    verify_lifecycle(!str_contains($active, 'mu-plugins') && str_contains($active, '/wp-content/plugins/'), 'Migrates static URL');
    verify_lifecycle(str_ends_with($active, $original), 'Retains unrelated rules');
    verify_lifecycle(count($cron) === 2, 'Schedules jobs');
    MCPELEE_SSG_Guard::deactivate();
    verify_lifecycle(file_get_contents($root . '.htaccess') === $original, 'Removes only owned rules');
    verify_lifecycle(!$cron, 'Removes scheduled jobs');
    verify_lifecycle(get_option('mcpelee_ssg_baseline_ready') === 1 && get_option('mcpelee_ssg_settings')['blocked'] === array('192.0.2.1'), 'Preserves settings and baseline');
    MCPELEE_SSG_Guard::activate();
    verify_lifecycle(file_get_contents($root . '.htaccess') === $active && count($cron) === 2, 'Reactivation restores saved policy and jobs');
    unlink($root . '.htaccess');
    file_put_contents($root . 'target', 'do not overwrite');
    symlink($root . 'target', $root . '.htaccess');
    try { MCPELEE_SSG_Guard::deactivate(); verify_lifecycle(false, 'Unsafe symlink accepted'); }
    catch (RuntimeException $e) { verify_lifecycle(str_contains($e->getMessage(), '비활성화를 중단'), 'Aborts failed deactivation'); }
    verify_lifecycle(count($cron) === 2 && file_get_contents($root . 'target') === 'do not overwrite', 'Failed deactivation leaves protection intact');
    echo "$checks lifecycle checks passed\n";
} finally {
    foreach (array('.htaccess', '.mcpelee-ssg-htaccess.lock', 'target') as $file) { if (file_exists($root . $file) || is_link($root . $file)) { unlink($root . $file); } }
    rmdir($root);
}

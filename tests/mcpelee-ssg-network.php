<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/class-mcpelee-ssg-network.php';
$n = 0;
function check($value, $message) { global $n; $n++; if (!$value) { throw new RuntimeException($message); } }
check(MCPELEE_SSG_Network::normalize('192.0.2.199/24') === '192.0.2.0/24', 'IPv4 canonical CIDR');
check(MCPELEE_SSG_Network::normalize('2001:db8::1/32') === '2001:db8::/32', 'IPv6 canonical CIDR');
check(MCPELEE_SSG_Network::contains('192.0.2.255', '192.0.2.0/24'), 'IPv4 inside');
check(!MCPELEE_SSG_Network::contains('192.0.3.0', '192.0.2.0/24'), 'IPv4 boundary');
check(MCPELEE_SSG_Network::contains('2001:db8:abcd::1', '2001:db8::/32'), 'IPv6 inside');
check(!MCPELEE_SSG_Network::contains('2001:db9::1', '2001:db8::/32'), 'IPv6 outside');
check(!MCPELEE_SSG_Network::contains('192.0.2.1', '::/0'), 'Address families separate');
check(MCPELEE_SSG_Network::contains('::1', '::/0'), 'IPv6 zero prefix');
check(MCPELEE_SSG_Network::contains('255.255.255.255', '0.0.0.0/0'), 'IPv4 zero prefix');
check(MCPELEE_SSG_Network::parse("192.0.2.1 # note\n192.0.2.1\n\n") === array('192.0.2.1'), 'Dedup/comment');
foreach (array('1.2.3.4/33','::1/129','1.2.3.4/-1','1.2.3.4/00','1.2.3.4/8/8',"1.2.3.4\"\nRewriteRule",'invalid') as $bad) {
    try { MCPELEE_SSG_Network::normalize($bad); check(false, 'Accepted malicious input'); } catch (InvalidArgumentException $e) { check(true, 'Rejected input'); }
}
$block = MCPELEE_SSG_Network::apache(array('192.0.2.0/24','2001:db8::/32'), array('192.0.2.3'), '/wp-content/plugins/site-security-guard/assets/blocked.html');
check(str_contains($block, "&& ! -R '192.0.2.3'"), 'Allow has priority');
$old = "# BEGIN WordPress\nRewriteRule . /index.php [L]\n# END WordPress\n";
check(MCPELEE_SSG_Network::merge($old, $block) === $block . $old, 'Prepends ahead of WP');
check(MCPELEE_SSG_Network::merge($block . $old, $block) === $block . $old, 'Idempotent');
try { MCPELEE_SSG_Network::merge('# BEGIN Site Security Guard', $block); check(false, 'Broken markers accepted'); } catch (RuntimeException $e) { check(true, 'Broken markers rejected'); }
try { MCPELEE_SSG_Network::apache(array(), array(), '/bad"path.html'); check(false, 'Path injection accepted'); } catch (InvalidArgumentException $e) { check(true, 'Path injection rejected'); }
$policy = array('blocked'=>array('192.0.2.1'), 'allowed'=>array('192.0.2.2'), 'country_enabled'=>1, 'country_blocked'=>array('CN','KR'), 'country_allowed'=>array('KR'));
check(MCPELEE_SSG_Network::policy_blocks('192.0.2.3', 'CN', $policy), 'Country deny');
check(!MCPELEE_SSG_Network::policy_blocks('192.0.2.3', 'KR', $policy), 'Country exemption');
check(MCPELEE_SSG_Network::policy_blocks('192.0.2.1', 'KR', $policy), 'IP deny priority');
check(!MCPELEE_SSG_Network::policy_blocks('192.0.2.2', 'CN', $policy), 'IP allow priority');
check(!MCPELEE_SSG_Network::policy_blocks('192.0.2.3', '', $policy), 'Unknown country fail open');
try { MCPELEE_SSG_Network::country_codes(array('XX')); check(false, 'Invalid country accepted'); } catch (InvalidArgumentException $e) { check(true, 'Country validated'); }
try { MCPELEE_SSG_Network::country_env('HTTP_X_COUNTRY'); check(false, 'Untrusted environment accepted'); } catch (InvalidArgumentException $e) { check(true, 'Environment constrained'); }
echo "$n checks passed\n";

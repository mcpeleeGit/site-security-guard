<?php
if (!defined('ABSPATH')) { exit; }
final class MCPELEE_SSG_Admin {
    private static $tabs = array('overview' => '대시보드', 'ip' => 'IP 차단', 'security' => '보안 설정', 'files' => '파일 검사', 'logs' => '로그');
    public static function url($tab, $args = array()) { return add_query_arg(array_merge(array('page' => 'site-security-guard', 'tab' => $tab), $args), admin_url('options-general.php')); }
    private static function form($op, $tab) {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="mcpelee_ssg_action"><input type="hidden" name="operation" value="' . esc_attr($op) . '"><input type="hidden" name="return_tab" value="' . esc_attr($tab) . '">';
        wp_nonce_field('mcpelee_ssg_action');
    }
    private static function toggle($s, $key, $title, $description) {
        echo '<label class="mcpelee-ssg-setting"><input type="checkbox" name="' . esc_attr($key) . '" value="1" ' . checked($s[$key], 1, false) . '><span><strong>' . esc_html($title) . '</strong><small>' . esc_html($description) . '</small></span></label>';
    }
    private static function card($title, $description = '') {
        echo '<section class="mcpelee-ssg-card"><h2>' . esc_html($title) . '</h2>';
        if ($description) { echo '<p class="mcpelee-ssg-muted">' . esc_html($description) . '</p>'; }
    }
    private static function link($tab, $label) { echo '<a class="button" href="' . esc_url(self::url($tab)) . '">' . esc_html($label) . '</a>'; }
    public static function render() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation/filtering; mutations have separate nonce checks.
        $tab = sanitize_key(wp_unslash($_GET['tab'] ?? 'overview'));
        if (!isset(self::$tabs[$tab])) { $tab = 'overview'; }
        $s = MCPELEE_SSG_Guard::settings(); $last = get_option('mcpelee_ssg_scan_last'); $scan = get_option('mcpelee_ssg_scan_state');
        $expected = MCPELEE_SSG_Network::apache($s['blocked'], $s['allowed'], MCPELEE_SSG_Guard::blocked_page_path(), $s);
        $current = is_readable(ABSPATH . '.htaccess') ? file_get_contents(ABSPATH . '.htaccess') : '';
        $synced = strpos($current, $expected) === 0;
        echo '<div class="wrap mcpelee-ssg-admin"><header class="mcpelee-ssg-heading"><div><h1>Site Security Guard</h1><p>사이트 접근 제어와 보안 기록을 한곳에서 관리하세요.</p></div><span class="mcpelee-ssg-badge">현재 IP · ' . esc_html(MCPELEE_SSG_Guard::ip() ?: '확인 불가') . '</span></header>';
        $notice = get_transient('mcpelee_ssg_notice_' . get_current_user_id());
        if ($notice) { delete_transient('mcpelee_ssg_notice_' . get_current_user_id()); echo '<div class="notice notice-' . ($notice['ok'] ? 'success' : 'error') . '"><p>' . esc_html($notice['text']) . '</p></div>'; }
        echo '<nav class="mcpelee-ssg-tabs" aria-label="보안 센터 메뉴">';
        foreach (self::$tabs as $key => $label) { echo '<a href="' . esc_url(self::url($key)) . '" ' . ($tab === $key ? 'class="is-active" aria-current="page"' : '') . '>' . esc_html($label) . '</a>'; }
        echo '</nav><div class="mcpelee-ssg-panel">';
        if ($tab === 'overview') {
            echo '<div class="mcpelee-ssg-stats">';
            foreach (array('차단 규칙' => count($s['blocked']) . '개', '허용 규칙' => count($s['allowed']) . '개', '로그인 보호' => $s['login_limit'] ? '사용 중' : '꺼짐', '파일 검사' => $scan ? '진행 중' : ($last ? esc_html(number_format_i18n($last['count'])) . '개 확인' : '미실행')) as $label => $value) { echo '<section class="mcpelee-ssg-stat"><span>' . esc_html($label) . '</span><strong>' . esc_html($value) . '</strong></section>'; }
            echo '</div><div class="mcpelee-ssg-grid">';
            self::card('서버 차단 상태');
            echo '<p class="mcpelee-ssg-status">' . ($synced ? '규칙 파일 반영됨' : '규칙 미적용 또는 변경됨') . '</p><p class="mcpelee-ssg-muted">규칙 파일 반영 여부와 실제 서버 동작은 다를 수 있습니다. 차단 IP에서 응답을 확인하세요.</p><p>서버 <code>' . esc_html(sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'] ?? 'unknown'))) . '</code></p>';
            self::link('ip', 'IP 정책 관리'); echo '</section>';
            self::card('최근 파일 검사');
            echo '<p class="mcpelee-ssg-status">' . ($last ? esc_html($last['finished']) : '검사를 시작해 주세요') . '</p><p class="mcpelee-ssg-muted">' . ($last ? 'UTC 기준 · 제외/읽기 실패 ' . (int)$last['skipped'] . '개' : '최초 검사로 파일 비교 기준값을 생성합니다.') . '</p>';
            self::link('files', '파일 검사 관리'); echo '</section></div>';
            self::card('빠른 시작', 'IP 차단 정책을 설정하고, 보안 옵션과 기록할 로그를 선택하세요.');
            echo '<div class="mcpelee-ssg-actions">'; self::link('security', '보안 설정'); self::link('logs', '보안 이력 보기'); echo '</div></section>';
            echo '<details class="mcpelee-ssg-card"><summary>긴급 복구 안내</summary><p>접근이 막혔다면 SSH/호스팅 파일 관리자에서 루트 .htaccess의 <code># BEGIN MCPELEE Site Security Guard</code>부터 <code># END MCPELEE Site Security Guard</code>까지 제거하세요. 이전 버전의 Site Security Guard 구간이 남아 있으면 함께 제거하세요.</p><p>이어서 wp-config.php에 <code>define(\'MCPELEE_SSG_EMERGENCY_DISABLE\', true);</code>를 추가하면 PHP IP/로그인 차단도 중지됩니다. 관리자에서 정책 수정 후 상수를 제거하세요.</p></details>';
        } elseif ($tab === 'ip') {
            self::card('IP 차단 및 허용', '한 줄에 IP 또는 CIDR을 입력하세요. IPv4/IPv6를 지원하며 허용 목록이 우선합니다.');
            self::form('save_ip', 'ip');
            echo '<div class="mcpelee-ssg-grid"><label class="mcpelee-ssg-field">차단 IP / CIDR<textarea name="blocked" rows="10" class="code" placeholder="192.0.2.10&#10;198.51.100.0/24">' . esc_textarea(implode("\n", $s['blocked'])) . '</textarea><small>지정한 주소의 요청을 정적 오류 페이지로 보냅니다.</small></label><label class="mcpelee-ssg-field">허용 IP / CIDR<textarea name="allowed" rows="10" class="code" placeholder="관리자 고정 IP">' . esc_textarea(implode("\n", $s['allowed'])) . '</textarea><small>관리자 고정 IP를 등록하면 실수로 차단되는 일을 줄일 수 있습니다.</small></label></div>';
            self::country_policy($s);
            submit_button('IP·국가 정책 저장 및 서버 적용'); echo '</form></section>';
            self::card('서버 적용 안내');
            echo '<p><strong>' . ($synced ? '규칙 파일 반영됨 · 실제 동작 확인 필요' : '규칙 미적용 또는 변경됨') . '</strong></p><p>Apache 2.4/LiteSpeed 호환 rewrite, AllowOverride FileInfo, mod_headers가 필요합니다. PHP 내장 서버와 Nginx는 .htaccess를 적용하지 않습니다.</p><p>정적 오류 페이지는 24시간 캐시합니다. IP별 302 응답은 private, no-store로 공유 캐시 오염을 막습니다. 서버 차단 요청은 Apache access log에서 확인하세요.</p><details><summary>프록시 및 검증 안내</summary><p>프록시 환경에서는 신뢰할 프록시만 설정해 REMOTE_ADDR를 복원해야 합니다. 차단된 외부 IP에서 302 → 정적 HTML 응답과 캐시 헤더를 확인하세요.</p></details></section>';
            self::card('로그인 임시 차단 해제', '로그인 실패로 잠긴 IP를 해제하고 실패 카운터를 초기화합니다. 위 IP 차단 목록은 변경하지 않습니다.');
            self::form('unlock', 'ip'); echo '<div class="mcpelee-ssg-actions"><label>해제할 IP <input name="unlock_ip" placeholder="192.0.2.10" required></label>'; submit_button('임시 차단 해제', 'secondary', 'submit', false); echo '</div></form></section>';
        } elseif ($tab === 'security') {
            self::card('사이트 보호', '필요한 보호 기능을 선택하세요. 이 탭의 저장은 IP 정책과 로그 설정을 변경하지 않습니다.');
            self::form('save_security', 'security');
            self::toggle($s, 'headers', '기본 보안 헤더', 'nosniff 및 Referrer-Policy 헤더를 적용합니다.');
            self::toggle($s, 'login_limit', '반복 로그인 실패 제한', '15분 내 실패 10회 시 해당 IP를 15분 임시 차단합니다. PHP 단계에서 동작합니다.');
            self::toggle($s, 'xmlrpc', 'XML-RPC 요청 차단', 'Jetpack 또는 외부 서비스 연동에 영향을 줄 수 있습니다.');
            self::toggle($s, 'hide_users', 'REST API 사용자 조회 제한', '비관리자의 사용자 목록 및 상세 조회를 제한합니다.');
            submit_button('보안 설정 저장'); echo '</form></section>';
        } elseif ($tab === 'files') {
            self::card('파일 변경 검사', '첫 검사는 기준값을 만들고, 다음 검사부터 파일 추가·수정·삭제를 기록합니다.');
            echo '<div class="mcpelee-ssg-callout"><strong>' . ($scan ? '검사 진행 중 · ' . esc_html(number_format_i18n($scan['count'])) . '개 처리' : '새 검사를 시작할 수 있습니다.') . '</strong>';
            if ($last) { echo '<p>최근 완료 ' . esc_html($last['finished']) . ' (UTC) · ' . esc_html(number_format_i18n($last['count'])) . '개 · 제외/읽기 실패 ' . (int)$last['skipped'] . '개</p>'; }
            echo '</div>'; self::form($scan ? 'step' : 'scan', 'files'); submit_button($scan ? '검사 계속 (다음 묶음)' : '파일 검사 시작'); echo '</form>';
            self::link('logs', '변경 이력 보기'); echo '</section>';
            self::card('자동 검사'); self::form('save_scanner', 'files'); self::toggle($s, 'daily_scan', '매일 파일 변경 검사', 'WP-Cron으로 실행합니다. 진행 중인 검사는 설정을 꺼도 완료까지 계속됩니다.'); submit_button('자동 검사 설정 저장', 'secondary'); echo '</form></section>';
            echo '<details class="mcpelee-ssg-card"><summary>검사 범위와 주의사항</summary><p>내용을 저장하지 않고 SHA-256만 저장합니다. 변경은 침입 확정이 아니며 최초 기준값의 안전성을 보장하지 않습니다.</p><p>심볼릭 링크, 캐시·업그레이드·.git 폴더, 16MB 초과 파일은 제외합니다. 업로드 폴더는 실행 가능한 확장자만 검사합니다. 오류와 제외 파일은 로그에서 확인하세요.</p></details>';
        } else {
            self::card('로그 수집 및 보관'); self::form('save_logging', 'logs');
            self::toggle($s, 'access_log', '워드프레스 접속 로그', '요청마다 DB 쓰기가 발생합니다. 정적 파일과 서버 단계에서 차단한 요청은 포함하지 않습니다.');
            self::toggle($s, 'country_lookup', 'IP 국가 조회', '켜면 로그 화면을 열 때 공인 IP를 ipwho.is에 HTTPS로 전송하여 국가를 조회합니다. 성공 결과는 30일 캐시하며 방문 요청에서는 조회하지 않습니다.');
            echo '<label class="mcpelee-ssg-field mcpelee-ssg-retention">보관 기간 (일)<input type="number" name="retention" min="1" max="90" value="' . esc_attr($s['retention']) . '"></label><p class="mcpelee-ssg-muted">매시간 정리 시 최신 20,000건까지 유지합니다. 시간 사이에는 일시 초과할 수 있습니다.</p>';
            submit_button('로그 설정 저장', 'secondary'); echo '</form></section>';
            self::logs();
        }
        echo '</div></div>';
    }
    private static function country_policy($s) {
        echo '<hr class="mcpelee-ssg-divider"><h2>국가별 차단 및 허용</h2>';
        self::toggle($s, 'country_enabled', '국가 차단 사용', '선택한 차단 국가의 요청을 정적 오류 페이지로 보냅니다. IP 허용 목록에 현재 관리자 IP를 먼저 등록하세요.');
        $detected = MCPELEE_SSG_Guard::server_country($s);
        echo '<div class="mcpelee-ssg-callout"><strong>' . ($detected ? '현재 요청의 서버 국가 정보: ' . esc_html($detected) : '현재 요청에서 서버 국가 정보를 확인할 수 없습니다.') . '</strong><p>Apache/LiteSpeed의 GeoIP 모듈과 국가 DB가 필요합니다. 로그 탭의 외부 국가 조회 기능과는 별개입니다. 서버 국가 정보가 없으면 국가 규칙은 적용되지 않고 IP 규칙만 적용됩니다.</p></div>';
        echo '<label class="mcpelee-ssg-field">서버 국가 변수<select name="country_env"><option value="MM_COUNTRY_CODE" ' . selected($s['country_env'],'MM_COUNTRY_CODE',false) . '>MM_COUNTRY_CODE (MaxMind DB)</option><option value="GEOIP_COUNTRY_CODE" ' . selected($s['country_env'],'GEOIP_COUNTRY_CODE',false) . '>GEOIP_COUNTRY_CODE (GeoIP / LiteSpeed)</option></select></label><div class="mcpelee-ssg-grid mcpelee-ssg-countries">';
        $options=MCPELEE_SSG_Network::country_options();
        foreach ($options as $code=>$name) { if (class_exists('Locale')) { $options[$code]=Locale::getDisplayRegion('und_'.$code,'ko'); } }
        asort($options, SORT_STRING);
        foreach (array('country_blocked'=>'차단 국가','country_allowed'=>'허용 국가 (국가 차단 예외)') as $key=>$label) {
            echo '<fieldset class="mcpelee-ssg-country-list"><legend>' . esc_html($label) . '</legend><div>';
            foreach ($options as $code=>$name) { echo '<label><input type="checkbox" name="' . esc_attr($key) . '[]" value="' . esc_attr($code) . '" ' . checked(in_array($code,$s[$key],true),true,false) . '> ' . esc_html($name . ' (' . $code . ')') . '</label>'; }
            echo '</div></fieldset>';
        }
        echo '</div><p class="mcpelee-ssg-muted">우선순위: IP 허용 → IP 차단 → 국가 허용 → 국가 차단. 국가 허용은 국가 차단의 예외이며, 허용 국가만 접속시키는 기능은 아닙니다. 미지정·판별 불가 국가는 허용합니다. 로그인 반복 실패 제한은 별도로 적용됩니다.</p><details><summary>서버 설정 안내</summary><p>Apache mod_maxminddb 예시 (서버 관리자 적용):</p><pre>MaxMindDBEnable On
MaxMindDBFile COUNTRY_DB /path/to/GeoLite2-Country.mmdb
MaxMindDBEnv MM_COUNTRY_CODE COUNTRY_DB/country/iso_code</pre><p>DB 경로와 모듈 설치·업데이트는 서버 환경에 맞춰 설정하세요. 클라이언트가 보낸 국가 헤더를 이 변수에 그대로 복사하면 우회될 수 있습니다. 저장 후 실제 차단 국가 IP에서 동작을 확인하세요.</p></details>';
    }
    private static function logs() {
        require_once __DIR__ . '/class-mcpelee-ssg-log-query.php';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation/filtering; mutations have separate nonce checks.
        $labels = MCPELEE_SSG_Log_Query::labels(); $input = map_deep(wp_unslash($_GET), 'sanitize_text_field');
        if (!isset($input['exclude_self'])) { $input['exclude_self'] = MCPELEE_SSG_Preferences::excluded() ? '1' : ''; }
        $s = MCPELEE_SSG_Log_Query::state($input);
        $url = function ($changes = array()) use ($s) { return self::url('logs', array_merge($s, array('log_page'=>1, 'mcpelee_ssg_pref_nonce'=>wp_create_nonce('mcpelee_ssg_preferences')), $changes)); };
        self::card('접속·보안·파일 변경 이력', '헤더를 눌러 정렬하고 날짜·종류·IP·국가·내용을 눌러 해당 값으로 조회하세요.');
        echo '<form method="get" action="' . esc_url(admin_url('options-general.php')) . '" class="mcpelee-ssg-actions"><input type="hidden" name="page" value="site-security-guard"><input type="hidden" name="tab" value="logs">';
        foreach (array('ip','country','date','detail','sort','order') as $key) { echo '<input type="hidden" name="' . esc_attr($key) . '" value="' . esc_attr($s[$key]) . '">'; }
        echo '<label for="mcpelee-ssg-kind">기록 종류</label><select id="mcpelee-ssg-kind" name="kind"><option value="">전체</option>';
        foreach ($labels as $key=>$label) { echo '<option value="' . esc_attr($key) . '" ' . selected($s['kind'],$key,false) . '>' . esc_html($label) . '</option>'; }
        echo '</select><input type="hidden" name="exclude_self" value="0"><input type="hidden" name="mcpelee_ssg_pref_nonce" value="' . esc_attr(wp_create_nonce('mcpelee_ssg_preferences')) . '">';
        echo '<label><input type="checkbox" name="exclude_self" value="1" ' . checked($s['exclude_self'],'1',false) . '> 현재 IP 제외 조회 <small>(' . esc_html(MCPELEE_SSG_Guard::ip() ?: '확인 불가') . ')</small></label><button class="button">조회</button><a href="' . esc_url(self::url('logs', array('exclude_self'=>'0', 'mcpelee_ssg_pref_nonce'=>wp_create_nonce('mcpelee_ssg_preferences')))) . '">초기화</a></form>';
        echo '<div class="mcpelee-ssg-filter-chips">';
        foreach (array('kind'=>'종류','ip'=>'IP','country'=>'국가','date'=>'날짜','detail'=>'내용','exclude_self'=>'현재 IP 제외') as $key=>$label) {
            if ($s[$key] === '') { continue; }
            $value = $key==='kind' ? ($labels[$s[$key]] ?? $s[$key]) : $s[$key];
            $text = $label . ($key==='exclude_self' ? '' : ': ' . mb_strimwidth($value,0,70,'…'));
            echo '<a class="mcpelee-ssg-chip" aria-label="' . esc_attr($text . ' 필터 해제') . '" href="' . esc_url($url(array($key=>''))) . '">' . esc_html($text) . ' ×</a>';
        }
        echo '</div>';
        $rows=MCPELEE_SSG_Log_Query::rows($s); $more=count($rows)>50; $rows=array_slice($rows,0,50);
        echo '<div class="mcpelee-ssg-table"><table class="widefat striped"><thead><tr>';
        foreach (array('created_at'=>'시간 (UTC)','kind'=>'종류','ip'=>'IP','country'=>'국가','detail'=>'내용') as $key=>$label) {
            $active=$s['sort']===$key; $next=$active && $s['order']==='asc'?'desc':'asc';
            echo '<th scope="col" aria-sort="' . ($active ? ($s['order']==='asc'?'ascending':'descending') : 'none') . '"><a href="' . esc_url($url(array('sort'=>$key,'order'=>$next))) . '" title="' . esc_attr($label . ' ' . ($next==='asc'?'오름차순':'내림차순') . ' 정렬') . '">' . esc_html($label) . ' <span aria-hidden="true">' . ($active ? ($s['order']==='asc'?'↑':'↓') : '↕') . '</span></a></th>';
        }
        echo '</tr></thead><tbody>';
        $cell = function ($text,$key,$value) use ($url) { return '<a class="mcpelee-ssg-filter-value" title="이 값으로 필터링" href="' . esc_url($url(array($key=>$value))) . '">' . esc_html($text) . '</a>'; };
        foreach ($rows as $r) {
            $country=MCPELEE_SSG_Country::initial($r->ip);
            echo '<tr><td>' . wp_kses_post($cell($r->created_at,'date',substr($r->created_at,0,10))) . '</td><td>' . (isset($labels[$r->kind]) ? wp_kses_post($cell($labels[$r->kind],'kind',$r->kind)) : esc_html($r->kind)) . '</td><td>' . ($r->ip ? wp_kses_post($cell($r->ip,'ip',$r->ip)) : '—') . '</td>';
            echo '<td class="mcpelee-ssg-country" data-filter-url="' . esc_url($url(array('country'=>''))) . '" data-ip="' . esc_attr($r->ip) . '" data-code="' . esc_attr($country['code'] ?? '') . '" data-pending="' . (!empty($country['pending']) && MCPELEE_SSG_Guard::settings()['country_lookup'] ? '1':'0') . '">' . (!empty($country['code']) ? wp_kses_post($cell($country['name'],'country',$country['code'])) : esc_html($country['name'])) . '</td><td>' . ($r->detail !== '' ? wp_kses_post($cell($r->detail,'detail',$r->detail)) : '—') . '</td></tr>';
        }
        if (!$rows) { echo '<tr><td colspan="5" class="mcpelee-ssg-empty">조건에 맞는 기록이 없습니다. 필터를 변경하거나 초기화하세요.</td></tr>'; }
        echo '</tbody></table></div><div class="mcpelee-ssg-actions mcpelee-ssg-pagination"><span>' . (int)$s['log_page'] . ' 페이지</span>';
        foreach (array(-1=>'이전',1=>'다음') as $delta=>$label) { if (($delta<0 && $s['log_page']>1) || ($delta>0 && $more)) { echo '<a class="button" href="' . esc_url($url(array('log_page'=>$s['log_page']+$delta))) . '">' . esc_html($label) . '</a>'; } }
        echo '</div><p class="mcpelee-ssg-muted">국가 필터·정렬은 조회 완료되어 캐시가 유효한 IP 기준입니다. 미조회 기록은 국가 필터에 포함되지 않습니다. 국가 조회 후 새로고침하면 정렬에 반영됩니다. 국가는 추정값이며 실제 위치와 다를 수 있습니다. 데이터: <a href="https://ipwhois.io/" target="_blank" rel="noopener noreferrer">IPWhois</a></p></section>';
    }
}

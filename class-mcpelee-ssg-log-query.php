<?php
if (!defined('ABSPATH')) { exit; }
final class MCPELEE_SSG_Log_Query {
    public static function labels() { return array('access'=>'접속','login_failed'=>'로그인 실패','login_lock'=>'로그인 차단','login_success'=>'로그인 성공','file_added'=>'파일 추가','file_changed'=>'파일 수정','file_deleted'=>'파일 삭제','scan_warning'=>'검사 경고','scan_complete'=>'검사 완료','settings'=>'설정 변경','unlock'=>'차단 해제','xmlrpc_blocked'=>'XML-RPC 차단'); }
    public static function state($input) {
        $value = function ($key, $default = '') use ($input) { return isset($input[$key]) && is_scalar($input[$key]) ? (string)$input[$key] : $default; };
        $kind = $value('kind'); $ip = $value('ip'); $country = strtoupper($value('country')); $date = $value('date'); $sort = $value('sort', 'created_at');
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $date) || !checkdate((int)substr($date,5,2),(int)substr($date,8,2),(int)substr($date,0,4))) { $date = ''; }
        return array('kind'=>isset(self::labels()[$kind]) ? $kind : '', 'ip'=>filter_var($ip,FILTER_VALIDATE_IP) ? $ip : '', 'country'=>preg_match('/^[A-Z]{2}$/D',$country) ? $country : '', 'date'=>$date, 'detail'=>mb_substr($value('detail'),0,2000), 'exclude_self'=>$value('exclude_self') === '1' ? '1' : '', 'sort'=>in_array($sort,array('created_at','kind','ip','country','detail'),true) ? $sort : 'created_at', 'order'=>strtolower($value('order','desc')) === 'asc' ? 'asc' : 'desc', 'log_page'=>max(1,min(100000,(int)$value('log_page','1'))));
    }
    public static function rows($s) {
        global $wpdb;
        $s = self::state($s);
        $self_ip = $s['exclude_self'] ? MCPELEE_SSG_Guard::ip() : '';
        // One prepare call: identifiers/order expressions are fixed; filters are values.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned security state requires current database reads/writes; no equivalent core API.
        return $wpdb->get_results($wpdb->prepare(
            "SELECT e.* FROM {$wpdb->prefix}mcpelee_ssg_events e
             LEFT JOIN {$wpdb->prefix}mcpelee_ssg_countries c ON c.ip=e.ip AND c.expires>%s
             WHERE (%s = '' OR e.kind=%s)
               AND (%s = '' OR e.ip=%s)
               AND (%s = '' OR e.detail=%s)
               AND (%s = '' OR e.ip<>%s)
               AND (%s = '' OR c.code=%s)
               AND (%s = '' OR (e.created_at >= %s AND e.created_at < DATE_ADD(%s, INTERVAL 1 DAY)))
             ORDER BY CASE WHEN %s = 'created_at' AND %s = 'asc' THEN e.created_at END ASC,
                CASE WHEN %s = 'created_at' AND %s = 'desc' THEN e.created_at END DESC,
                CASE WHEN %s = 'kind' AND %s = 'asc' THEN CASE e.kind WHEN 'access' THEN '접속' WHEN 'login_failed' THEN '로그인 실패' WHEN 'login_lock' THEN '로그인 차단' WHEN 'login_success' THEN '로그인 성공' WHEN 'file_added' THEN '파일 추가' WHEN 'file_changed' THEN '파일 수정' WHEN 'file_deleted' THEN '파일 삭제' WHEN 'scan_warning' THEN '검사 경고' WHEN 'scan_complete' THEN '검사 완료' WHEN 'settings' THEN '설정 변경' WHEN 'unlock' THEN '차단 해제' WHEN 'xmlrpc_blocked' THEN 'XML-RPC 차단' ELSE e.kind END END ASC,
                CASE WHEN %s = 'kind' AND %s = 'desc' THEN CASE e.kind WHEN 'access' THEN '접속' WHEN 'login_failed' THEN '로그인 실패' WHEN 'login_lock' THEN '로그인 차단' WHEN 'login_success' THEN '로그인 성공' WHEN 'file_added' THEN '파일 추가' WHEN 'file_changed' THEN '파일 수정' WHEN 'file_deleted' THEN '파일 삭제' WHEN 'scan_warning' THEN '검사 경고' WHEN 'scan_complete' THEN '검사 완료' WHEN 'settings' THEN '설정 변경' WHEN 'unlock' THEN '차단 해제' WHEN 'xmlrpc_blocked' THEN 'XML-RPC 차단' ELSE e.kind END END DESC,
                CASE WHEN %s = 'ip' AND %s = 'asc' THEN INET6_ATON(e.ip) END ASC,
                CASE WHEN %s = 'ip' AND %s = 'desc' THEN INET6_ATON(e.ip) END DESC,
                CASE WHEN %s = 'country' AND %s = 'asc' THEN COALESCE(c.name, '') END ASC,
                CASE WHEN %s = 'country' AND %s = 'desc' THEN COALESCE(c.name, '') END DESC,
                CASE WHEN %s = 'detail' AND %s = 'asc' THEN e.detail END ASC,
                CASE WHEN %s = 'detail' AND %s = 'desc' THEN e.detail END DESC,
                CASE WHEN %s = 'asc' THEN e.id END ASC,
                CASE WHEN %s = 'desc' THEN e.id END DESC
             LIMIT 51 OFFSET %d",
            gmdate('Y-m-d H:i:s'),
            $s['kind'], $s['kind'], $s['ip'], $s['ip'], $s['detail'], $s['detail'],
            $self_ip, $self_ip, $s['country'], $s['country'],
            $s['date'], $s['date'] . ' 00:00:00', $s['date'] . ' 00:00:00',
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['sort'],
            $s['order'],
            $s['order'],
            $s['order'],
            ($s['log_page'] - 1) * 50
        ));
    }
}

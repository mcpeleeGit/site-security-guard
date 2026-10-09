<?php
/** Pure IP validation and Apache rule generation; also used by the standalone tests. */
final class MCPELEE_SSG_Network {
    public static function normalize($value) {
        $parts = explode('/', trim($value));
        if (count($parts) > 2 || !filter_var($parts[0], FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException('유효하지 않은 IP/CIDR입니다.');
        }
        $packed = inet_pton($parts[0]);
        $bits = strlen($packed) * 8;
        $prefix = $bits;
        if (isset($parts[1])) {
            if (!preg_match('/^(0|[1-9][0-9]{0,2})$/D', $parts[1]) || (int)$parts[1] > $bits) {
                throw new InvalidArgumentException('유효하지 않은 CIDR입니다.');
            }
            $prefix = (int)$parts[1];
        }
        for ($i = 0; $i < strlen($packed); $i++) {
            $remaining = max(0, min(8, $prefix - $i * 8));
            $packed[$i] = chr(ord($packed[$i]) & ($remaining ? (255 << (8 - $remaining)) & 255 : 0));
        }
        return inet_ntop($packed) . ($prefix === $bits ? '' : '/' . $prefix);
    }
    public static function parse($text) {
        $result = array();
        foreach (preg_split('/\R/', $text) as $line) {
            $line = trim(explode('#', $line, 2)[0]);
            if ($line !== '') { $result[] = self::normalize($line); }
        }
        $result = array_values(array_unique($result));
        if (count($result) > 1000) { throw new InvalidArgumentException('최대 1,000개 규칙을 사용할 수 있습니다.'); }
        return $result;
    }
    public static function contains($ip, $network) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
        $parts = explode('/', self::normalize($network));
        $a = inet_pton($ip); $b = inet_pton($parts[0]);
        if (strlen($a) !== strlen($b)) { return false; }
        $bits = isset($parts[1]) ? (int)$parts[1] : strlen($b) * 8;
        for ($i = 0; $i < strlen($b); $i++) {
            $n = max(0, min(8, $bits - $i * 8));
            $mask = $n ? (255 << (8 - $n)) & 255 : 0;
            if ((ord($a[$i]) & $mask) !== ord($b[$i])) { return false; }
        }
        return true;
    }
    public static function matches($ip, $rules) {
        foreach ($rules as $rule) { if (self::contains($ip, $rule)) { return true; } }
        return false;
    }
    public static function country_options() {
        static $options;
        if ($options === null) { $options = json_decode(file_get_contents(__DIR__ . '/assets/mcpelee-ssg-countries.json'), true); }
        return $options;
    }
    public static function country_codes($codes) {
        if (!is_array($codes)) { throw new InvalidArgumentException('국가 목록 형식이 올바르지 않습니다.'); }
        $valid = self::country_options(); $result = array();
        foreach ($codes as $code) {
            if (!is_string($code) || !isset($valid[strtoupper($code)])) { throw new InvalidArgumentException('유효하지 않은 국가 코드입니다.'); }
            $result[] = strtoupper($code);
        }
        return array_values(array_unique($result));
    }
    public static function country_env($env) {
        if (!in_array($env, array('MM_COUNTRY_CODE','GEOIP_COUNTRY_CODE'), true)) { throw new InvalidArgumentException('지원하지 않는 GeoIP 서버 변수입니다.'); }
        return $env;
    }
    public static function policy_blocks($ip, $country, $s) {
        if (self::matches($ip, $s['allowed'])) { return false; }
        if (self::matches($ip, $s['blocked'])) { return true; }
        return !empty($s['country_enabled']) && in_array($country, $s['country_blocked'], true) && !in_array($country, $s['country_allowed'], true);
    }
    public static function apache($blocked, $allowed, $path, $policy = array()) {
        // Deliberately reject arbitrary URLs and Apache expression metacharacters.
        if (!preg_match('~^/[a-zA-Z0-9_./-]+\.html$~D', $path) || strpos($path, '..') !== false) {
            throw new InvalidArgumentException('정적 페이지 경로에는 영문/숫자/밑줄/하이픈만 사용할 수 있습니다.');
        }
        $out = "# BEGIN MCPELEE Site Security Guard\n<IfModule mod_rewrite.c>\nRewriteEngine On\n";
        $countries = !empty($policy['country_enabled']) ? self::country_codes($policy['country_blocked'] ?? array()) : array();
        $exceptions = self::country_codes($policy['country_allowed'] ?? array());
        $env = self::country_env($policy['country_env'] ?? 'MM_COUNTRY_CODE');
        if ($blocked || $countries) {
            $conditions = array();
            foreach ($blocked as $rule) { $conditions[] = "-R '" . self::normalize($rule) . "'"; }
            if ($countries) {
                $country = "reqenv('$env') =~ /^(" . implode('|', $countries) . ")$/";
                if ($exceptions) { $country .= " && !(reqenv('$env') =~ /^(" . implode('|', $exceptions) . ")$/)"; }
                $conditions[] = '(' . $country . ')';
            }
            $expr = '(' . implode(' || ', $conditions) . ')';
            foreach ($allowed as $rule) { $expr .= " && ! -R '" . self::normalize($rule) . "'"; }
            $out .= 'RewriteCond %{REQUEST_URI} !^' . preg_quote($path, '~') . "$\n";
            $out .= 'RewriteCond expr "' . $expr . '"' . "\n";
            // Relative fixed destination: never use the untrusted Host header in generated config.
            $out .= 'RewriteRule ^ ' . $path . " [R=302,END,NE,QSD,E=MCPELEE_SSG_BLOCK:1]\n";
        }
        $out .= "</IfModule>\n<IfModule mod_headers.c>\nHeader always set Cache-Control \"private, no-store\" env=MCPELEE_SSG_BLOCK\nHeader always set Cache-Control \"private, no-store\" env=REDIRECT_MCPELEE_SSG_BLOCK\n</IfModule>\n# END MCPELEE Site Security Guard\n";
        $static_headers = '<IfModule mod_headers.c>' . "\n";
        $condition = '"expr=%{REQUEST_URI} == \'' . $path . '\' && %{REQUEST_STATUS} == 200"';
        foreach (array('Cache-Control'=>'public, max-age=86400', 'X-Content-Type-Options'=>'nosniff', 'X-Robots-Tag'=>'noindex, nofollow') as $name=>$value) {
            $static_headers .= 'Header set ' . $name . ' "' . $value . '" ' . $condition . "\n";
        }
        $static_headers .= "</IfModule>\n";
        $out = str_replace('# END MCPELEE Site Security Guard', $static_headers . '# END MCPELEE Site Security Guard', $out);
        return $out;
    }
    public static function merge($existing, $block) {
        // Recognize the development-era marker solely for upgrades and deactivation cleanup.
        foreach (array('Site Security Guard', 'MCPELEE Site Security Guard') as $marker) {
            $begin = '# BEGIN ' . $marker; $end = '# END ' . $marker;
            if (substr_count($existing, $begin) !== substr_count($existing, $end) || substr_count($existing, $begin) > 1) {
                throw new RuntimeException('.htaccess 관리 구간이 손상되어 자동 수정을 중단했습니다.');
            }
            if (strpos($existing, $begin) !== false && strpos($existing, $end) < strpos($existing, $begin)) {
                throw new RuntimeException('.htaccess 관리 구간 순서가 잘못되었습니다.');
            }
            $existing = preg_replace('/^' . preg_quote($begin, '/') . '\R.*?^' . preg_quote($end, '/') . '(?:\R|$)/ms', '', $existing);
            if (strpos($existing, $begin) !== false) { throw new RuntimeException('.htaccess 관리 구간을 해석할 수 없습니다.'); }
        }
        return $block . $existing;
    }
}

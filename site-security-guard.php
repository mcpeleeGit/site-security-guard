<?php
/*
Plugin Name: Site Security Guard
Description: IP·국가별 접근 제어, 정적 오류 페이지 리다이렉트, 접속·보안 로그 및 파일 변경 감시를 제공하는 보안 플러그인
Version: 1.0.0
Requires at least: 6.0
Requires PHP: 8.0
Author: mcpelee
Author URI: https://github.com/mcpeleeGit
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: site-security-guard
*/

/*  Copyright 2026 mcpelee

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see https://www.gnu.org/licenses/.
*/

if (!defined('ABSPATH')) { exit; }
define('MCPELEE_SSG_PLUGIN_FILE', __FILE__);
require_once __DIR__ . '/class-mcpelee-ssg-network.php';
require_once __DIR__ . '/class-mcpelee-ssg-guard.php';
require_once __DIR__ . '/class-mcpelee-ssg-scanner.php';
require_once __DIR__ . '/class-mcpelee-ssg-country.php';
require_once __DIR__ . '/class-mcpelee-ssg-preferences.php';
add_action('admin_init', array('MCPELEE_SSG_Preferences', 'from_form'));
add_action('wp_ajax_mcpelee_ssg_preferences', array('MCPELEE_SSG_Preferences', 'ajax'));
require_once __DIR__ . '/class-mcpelee-ssg-migration.php';
add_action('init', array('MCPELEE_SSG_Migration', 'run'), -1);
MCPELEE_SSG_Guard::boot();

register_activation_hook(__FILE__, array('MCPELEE_SSG_Guard', 'activate'));
register_deactivation_hook(__FILE__, array('MCPELEE_SSG_Guard', 'deactivate'));
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    array_unshift($links, '<a href="' . esc_url(admin_url('options-general.php?page=site-security-guard')) . '">보안 설정</a>');
    return $links;
});

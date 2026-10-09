=== Site Security Guard ===
Contributors: mcpelee
Tags: security, ip blocking, access log, file integrity, country blocking
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Manage IP and country access rules, static error redirects, security logs, login protection, and file change monitoring.

== Description ==

Site Security Guard provides access control and security monitoring through Settings > Site Security Guard. The dashboard includes IP blocking, security settings, file scanning, and logs. The administration interface is currently in Korean.

= Features =

* IPv4, IPv6, and CIDR block and allow lists.
* Apache-compatible redirects to a static error page before WordPress runs.
* A 24-hour cache policy for the static page; IP-dependent redirects use private, no-store.
* Country blocking with country allow exceptions using server-provided GeoIP information.
* Temporary login failure limits, security headers, optional XML-RPC blocking, and REST user lookup restrictions.
* Optional access logs and country lookup, sorting, clickable filters, and per-administrator preferences.
* SHA-256 file change monitoring and optional daily scans through WP-Cron.

= Server requirements =

WordPress 6.0 or later, PHP 8.0 or later, and a single-site installation are required.

Server-level blocking requires Apache 2.4 with mod_rewrite, mod_headers, AllowOverride FileInfo, or a compatible LiteSpeed configuration. The installation root .htaccess must be writable. Saving the IP policy generates both blocking and static-page header rules in a plugin-managed section. No hidden .htaccess file is shipped inside the plugin.

Nginx and the PHP development server do not process .htaccess. PHP fallback protection applies to WordPress requests, not every static file. A CDN that serves responses before reaching the origin needs its own access rules. Trusted proxies must restore the real client IP at the server level.

Country blocking requires a server GeoIP module and database providing MM_COUNTRY_CODE or GEOIP_COUNTRY_CODE before rewrite processing. The plugin does not install these dependencies. Requests with unknown countries are not country-blocked. IP allow rules take priority over IP block rules, followed by country allow exceptions and country blocks. A country allow list is not an exclusive list of permitted countries.

= Storage and retention =

Optional access logs store the IP, request method, URL path, and response status. Query strings, request bodies, passwords, and cookies are not logged. Sensitive data embedded in URL paths may still be recorded. Access logging adds one database write per WordPress request. Requests blocked by the web server are available in server logs, not plugin logs.

Logs default to seven days of retention, configurable from 1 to 90 days. Hourly cleanup retains at most 20,000 recent records; the count can exceed this between cleanup runs. File scans store paths and hashes, not original file contents. Detected changes are investigation clues, not proof of intrusion or a malware diagnosis.

Deactivation removes the plugin-managed server rules and scheduled tasks. Settings, logs, country cache, file baselines, and administrator preferences remain in the database after deactivation or deletion.

= Distribution and compatibility =

Classes and constants use MCPELEE_SSG_; hooks, options, caches, and database tables use mcpelee_ssg_. Internal filenames and CSS identifiers use mcpelee-ssg-. Legacy development identifiers are recognized only for migration or compatibility.

Standard WordPress filenames, the main plugin filename, and the static error page URL remain stable. Developer tests and build scripts are excluded from the release ZIP. No custom Update URI header is used.

== Installation ==

1. Upload the release ZIP using Plugins > Add New, or copy its site-security-guard folder into wp-content/plugins.
2. Activate Site Security Guard.
3. Open Settings > Site Security Guard and add your fixed administrator IP to the IP allow list.
4. Enter blocked IPs or CIDRs and save the IP/country policy to apply server rules.
5. Verify redirects from an actual blocked IP and normal access from an allowed IP.
6. Run the first file scan to establish a baseline, then enable the desired security, logging, and scheduled scan options.

When replacing a development build, back up files and the database first. Replace the entire plugin folder so obsolete files, including tests, do not remain. Development-table migration requires database permission to rename tables. Older MU-plugin loaders must be removed before activating this plugin.

== Frequently Asked Questions ==

= Does activation enable every feature? =

Basic security headers and repeated-login-failure protection are enabled by default. Configure and save IP rules separately. Access logging, external country lookup, and daily scanning are optional.

= Does country blocking use the external country lookup service? =

No. Country blocking uses server GeoIP environment variables. The optional external lookup only enriches log displays. Without server GeoIP information, country blocking does not work.

= When do file scans run? =

Scans start manually or through the optional daily schedule and continue in bounded WP-Cron batches. Low-traffic sites may need a server cron job to trigger WP-Cron reliably. Symbolic links, certain cache and upgrade directories, and files larger than 16 MB are excluded. In uploads, only executable or active-content extensions are checked. The first baseline does not prove the files are safe.

= How do I recover from administrator lockout? =

Using SSH or your hosting file manager, remove the root .htaccess section between # BEGIN MCPELEE Site Security Guard and # END MCPELEE Site Security Guard. Remove any remaining development-era Site Security Guard section too. Temporarily add define('MCPELEE_SSG_EMERGENCY_DISABLE', true); before WordPress loads in wp-config.php, correct the rules, and remove the constant afterward. This constant alone cannot bypass Apache rules.

= Is the current-IP exclusion preference remembered? =

Yes. The choice is saved per administrator and site, including the unchecked state. Apply the query to refresh the list. Filtering does not delete records.

== External services ==

= IPWhois country lookup (optional) =

This feature is disabled by default and runs only after an administrator enables IP country lookup in the Logs tab.

* Purpose: Display an estimated country for logged IP addresses.
* Timing: When an administrator views logs, visible public IPs without a valid cache are queried asynchronously. Visitor requests do not trigger external lookups.
* Data sent: The public IP being queried is included in the HTTPS request path to https://ipwho.is/. The provider can also see the server's source IP and standard WordPress HTTP client information. Account information, cookies, and log message contents are not included as request data.
* Caching: Successful results are cached for 30 days and failures for one hour. Private and reserved addresses are not queried. Estimates may differ from the visitor's actual location and do not establish historical location.
* Documentation: https://ipwhois.io/documentation
* Terms: https://ipwhois.io/terms
* Privacy policy: https://ipwhois.io/privacy

Server GeoIP country blocking does not call this API. Server administrators separately manage their GeoIP module, database updates, and the applicable provider terms.

== Changelog ==

= 1.0.0 =
* Initial release with IP/country access rules, static error redirects, login protection, file monitoring, and security logs.
* Log filtering, sorting, country enrichment, and per-administrator IP exclusion preferences.
* WordPress.org distribution metadata and runtime-only packaging.

== Upgrade Notice ==

= 1.0.0 =
Initial release. Back up files and the database before replacing a development build. Replace the entire folder to remove obsolete files. Schema migration may require table rename permissions.

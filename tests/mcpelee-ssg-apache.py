"""Isolated Apache 2.4 regression test. Does not modify the WordPress installation."""
import http.client, json, os, pathlib, pwd, shutil, socket, subprocess, tempfile, time
plugin = pathlib.Path(__file__).resolve().parent.parent
httpd = shutil.which('httpd') or '/usr/sbin/httpd'
modules = pathlib.Path(os.environ.get('APACHE_MODULES', '/usr/libexec/apache2'))
with tempfile.TemporaryDirectory(prefix='mcpelee-ssg-apache-') as temp:
    root = pathlib.Path(temp); root.chmod(0o755)
    doc = root / 'public'; doc.mkdir(); doc.chmod(0o755)
    asset = doc / 'blocked'; asset.mkdir()
    shutil.copy(plugin / 'assets/blocked.html', asset / 'blocked.html')
    (doc / 'handler.txt').write_text('APPLICATION REACHED')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    lines = [f'ServerRoot "{root}"', f'Listen 127.0.0.1:{port}', 'ServerName localhost', f'PidFile "{root}/httpd.pid"', f'ErrorLog "{root}/error.log"']
    for mod in ['mpm_prefork','unixd','authz_core','rewrite','headers','mime']:
        lines.append(f'LoadModule {mod}_module "{modules}/mod_{mod}.so"')
    lines += [f'User {pwd.getpwuid(os.getuid()).pw_name}', 'Group staff' if os.uname().sysname == 'Darwin' else f'Group #{os.getgid()}', f'TypesConfig /etc/apache2/mime.types', f'DocumentRoot "{doc}"', f'<Directory "{doc}">', 'Require all granted', 'AllowOverride FileInfo', '</Directory>']
    config = root / 'httpd.conf'; config.write_text('\n'.join(lines))
    def policy(blocked, allowed, countries=None, server_country=""):
        code = 'require ' + json.dumps(str(plugin / 'class-mcpelee-ssg-network.php')) + '; echo MCPELEE_SSG_Network::apache(json_decode($argv[1],true),json_decode($argv[2],true),"/blocked/blocked.html",json_decode($argv[3],true));'
        rules = subprocess.check_output(['php','-r',code,json.dumps(blocked),json.dumps(allowed),json.dumps(countries or {})], text=True)
        prefix = ('RewriteEngine On\nRewriteRule ^ - [E=MM_COUNTRY_CODE:' + server_country + ']\n') if server_country else ''
        (doc / '.htaccess').write_text(prefix + rules + '\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ handler.txt [END]\n')
    def request(path, headers=None):
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=3); c.request('GET', path, headers=headers or {})
        r = c.getresponse(); result = (r.status, dict((k.lower(),v) for k,v in r.getheaders()),r.read().decode()); c.close(); return result
    policy(['127.0.0.0/8'], [])
    subprocess.run([httpd, '-t','-f',str(config)], check=True)
    server = subprocess.Popen([httpd,'-X','-f',str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                status, headers, body = request('/wp-login.php?secret=discard'); break
            except OSError: time.sleep(.1)
        else: raise RuntimeError(server.stderr.read().decode())
        assert status == 302, (status, body, (root/'error.log').read_text())
        assert headers['location'].endswith('/blocked/blocked.html') and '?' not in headers['location'], headers
        assert headers.get('cache-control') == 'private, no-store', headers
        assert request('/handler.txt')[0] == 302, 'Existing static files also blocked'
        assert request('/wp-json/', {'X-Forwarded-For':'192.0.2.1'})[0] == 302, 'Spoofed proxy header bypass'
        status, headers, body = request('/blocked/blocked.html')
        assert status == 200 and '접근이 제한' in body
        assert headers.get('cache-control') == 'public, max-age=86400', headers
        assert headers.get('x-content-type-options') == 'nosniff', headers
        assert headers.get('x-robots-tag') == 'noindex, nofollow', headers
        policy(['127.0.0.0/8'], ['127.0.0.1'])
        status, headers, body = request('/wp-login.php')
        assert status == 200 and body == 'APPLICATION REACHED', (status, body)
        assert 'cache-control' not in headers, headers
        (doc / 'blocked.html').write_text('Unrelated file')
        assert 'cache-control' not in request('/blocked.html')[1], 'Unrelated same-named files must not inherit caching'
        policy(['192.0.2.0/24','2001:db8::/32'], [])
        assert request('/wp-json/')[2] == 'APPLICATION REACHED', 'Unblocked address affected'
        policy([], [])
        assert request('/wp-admin/')[2] == 'APPLICATION REACHED'
        country_policy = {'country_enabled':1, 'country_blocked':['CN','KR'], 'country_allowed':['KR'], 'country_env':'MM_COUNTRY_CODE'}
        policy([], [], country_policy, 'CN')
        assert request('/wp-login.php')[0] == 302, 'Country blocked before application'
        assert request('/blocked/blocked.html')[0] == 200, 'Country block static page exempt'
        policy([], [], country_policy, 'KR')
        assert request('/wp-login.php')[0] == 200, 'Country allow exception'
        policy(['127.0.0.1'], [], country_policy, 'KR')
        assert request('/wp-login.php')[0] == 302, 'Explicit IP block wins over country exception'
        policy([], ['127.0.0.1'], country_policy, 'CN')
        assert request('/wp-login.php')[0] == 200, 'IP allow wins over country block'
        policy([], [], country_policy)
        assert request('/wp-login.php', {'MM_COUNTRY_CODE':'CN', 'X-Country-Code':'CN'})[0] == 200, 'Missing country and spoofed headers do not trigger rules'
        country_policy['country_enabled'] = 0
        policy([], [], country_policy, 'CN')
        assert request('/wp-login.php')[0] == 200, 'Disabled country policy'
        print('Country rules: blocked, allowed, IP priorities, missing data, spoofed headers and disabled policy passed')
        print('Apache: redirect, CIDR, allow priority, static cache, no redirect cache, query removal, header spoof, normal routing passed')
    finally:
        server.terminate(); server.wait(timeout=5)

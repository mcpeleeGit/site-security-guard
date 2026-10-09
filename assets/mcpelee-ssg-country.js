(() => {
    'use strict';
    const cells = [...document.querySelectorAll('.mcpelee-ssg-country')];
    let names;
    try { names = new Intl.DisplayNames(['ko'], {type: 'region'}); } catch (_) {}
    const show = (cell, data) => {
        const text = data.code && names ? `${names.of(data.code)} (${data.code})` : data.name || '확인 불가';
        if (data.code && cell.dataset.filterUrl) {
            const url = new URL(cell.dataset.filterUrl);
            url.searchParams.set('country', data.code);
            const link = document.createElement('a');
            link.href = url.toString(); link.textContent = text;
            link.className = 'mcpelee-ssg-filter-value'; link.title = '이 국가로 필터링';
            cell.replaceChildren(link);
        } else { cell.textContent = text; }
    };
    cells.filter(cell => cell.dataset.code).forEach(cell => show(cell, {code: cell.dataset.code, name: cell.textContent}));
    const ips = [...new Set(cells.filter(cell => cell.dataset.pending === '1').map(cell => cell.dataset.ip))];
    async function run() {
        for (let i = 0; i < ips.length; i += 5) {
            const batch = ips.slice(i, i + 5);
            const body = new URLSearchParams({action: 'mcpelee_ssg_country', _ajax_nonce: mcpeleeSsgCountry.nonce});
            batch.forEach(ip => body.append('ips[]', ip));
            try {
                const response = await fetch(mcpeleeSsgCountry.url, {method: 'POST', credentials: 'same-origin', body});
                const payload = await response.json();
                if (!response.ok || !payload.success) throw new Error('lookup failed');
                cells.filter(cell => batch.includes(cell.dataset.ip)).forEach(cell => show(cell, payload.data[cell.dataset.ip] || {name: '확인 불가'}));
            } catch (_) {
                cells.filter(cell => ips.slice(i).includes(cell.dataset.ip)).forEach(cell => { cell.textContent = '조회 지연 · 새로고침'; });
                break;
            }
        }
    }
    if (mcpeleeSsgCountry.enabled) run();
})();

(() => {
    const checkbox = document.querySelector('input[type="checkbox"][name="exclude_self"]');
    if (!checkbox) return;
    let saving = Promise.resolve();
    checkbox.addEventListener('change', () => {
        const value = checkbox.checked ? '1' : '0';
        saving = saving.catch(() => {}).then(async () => {
            const body = new URLSearchParams({action: 'mcpelee_ssg_preferences', _ajax_nonce: mcpeleeSsgPreferences.nonce, exclude_self: value});
            try {
                const response = await fetch(mcpeleeSsgPreferences.url, {method: 'POST', credentials: 'same-origin', body, keepalive: true});
                const result = await response.json();
                if (!response.ok || !result.success) throw new Error();
                status.textContent = '선택 저장됨 · 조회를 누르면 목록에 적용됩니다.';
            } catch (_) { status.textContent = '선택 저장 실패 · 조회 버튼을 눌러 다시 저장하세요.'; }
        });
    });
    const status = document.createElement('span');
    status.className = 'mcpelee-ssg-muted'; status.setAttribute('role', 'status');
    checkbox.closest('form').append(status);
})();

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-toggle-password]').forEach(button => {
        button.addEventListener('click', () => {
            const selector = button.getAttribute('data-toggle-password');
            const input = selector ? document.querySelector(selector) : null;
            if (!input) return;

            input.type = input.type === 'password' ? 'text' : 'password';
            button.textContent = input.type === 'password' ? '👁' : '🙈';
        });
    });

    document.querySelectorAll('[data-copy-value]').forEach(button => {
        button.addEventListener('click', async () => {
            const value = button.getAttribute('data-copy-value') || '';

            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(value);
                } else {
                    const temp = document.createElement('textarea');
                    temp.value = value;
                    temp.style.position = 'fixed';
                    temp.style.opacity = '0';
                    document.body.appendChild(temp);
                    temp.select();
                    document.execCommand('copy');
                    temp.remove();
                }

                const oldText = button.textContent;
                button.textContent = '✓';
                showCopyFlash('Скопировано');
                setTimeout(() => {
                    button.textContent = oldText;
                }, 1400);
            } catch (error) {
                showCopyFlash('Не удалось скопировать', true);
            }
        });
    });

    function showCopyFlash(text, isError = false) {
        const old = document.querySelector('.copy-flash');
        if (old) old.remove();

        const flash = document.createElement('div');
        flash.className = 'copy-flash';
        flash.textContent = text;
        if (isError) {
            flash.style.borderColor = 'rgba(241,109,102,.35)';
            flash.style.color = '#ff9b95';
            flash.style.background = '#2a1718';
        }
        document.body.appendChild(flash);
        setTimeout(() => flash.remove(), 1600);
    }
});

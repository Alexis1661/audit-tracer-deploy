(() => {
    const storageKey = 'audit-tracer.appearance';
    const root = document.documentElement;
    const darkSystemTheme = window.matchMedia('(prefers-color-scheme: dark)');
    const themes = ['system', 'light', 'dark'];
    const sizes = ['normal', 'large', 'extra-large'];

    function loadPreferences() {
        let saved;
        try {
            saved = JSON.parse(localStorage.getItem(storageKey));
        } catch {
            // La página también funciona cuando el navegador bloquea el almacenamiento.
        }
        return {
            theme: themes.includes(saved?.theme) ? saved.theme : 'system',
            size: sizes.includes(saved?.size) ? saved.size : 'normal',
            contrast: saved?.contrast === true,
        };
    }

    let preferences = loadPreferences();

    function applyPreferences() {
        root.dataset.auditTheme = preferences.theme === 'system'
            ? (darkSystemTheme.matches ? 'dark' : 'light')
            : preferences.theme;
        root.dataset.auditSize = preferences.size;
        root.dataset.auditContrast = String(preferences.contrast);
    }

    applyPreferences();
    darkSystemTheme.addEventListener('change', applyPreferences);

    document.addEventListener('DOMContentLoaded', () => {
        const controls = document.querySelectorAll('[data-audit-setting]');
        const appearance = document.querySelector('.audit-appearance');
        const search = document.querySelector('#audit-global-query');
        const unread = document.querySelector('#audit-unread');

        if (unread) {
            const status = document.querySelector('#audit-unread-status');
            const notifications = unread.closest('a');
            let loadingUnread = false;
            const refreshUnread = async () => {
                if (document.hidden || loadingUnread) return;
                loadingUnread = true;
                try {
                    const response = await fetch(unread.dataset.url, {
                        redirect: 'error', signal: AbortSignal.timeout(8000),
                    });
                    if (!response.ok) return;
                    const data = await response.json();
                    const count = data.unread;
                    const label = count > 0 ? `Notificaciones, ${count} sin leer` : 'Notificaciones';
                    if (notifications.getAttribute('aria-label') !== label) {
                        notifications.setAttribute('aria-label', label);
                        status.textContent = count > 0 ? label : 'No tienes notificaciones sin leer.';
                    }
                    unread.hidden = !(count > 0);
                    unread.textContent = count > 99 ? '99+' : String(count);
                } catch {
                    // Se recupera en la próxima consulta.
                } finally {
                    loadingUnread = false;
                }
            };
            refreshUnread();
            window.setInterval(refreshUnread, 30000);
            document.addEventListener('visibilitychange', refreshUnread);
        }

        function syncControls() {
            for (const control of controls) {
                const value = preferences[control.dataset.auditSetting];
                if (control.type === 'checkbox') control.checked = value;
                else control.value = value;
            }
        }

        syncControls();
        for (const control of controls) {
            control.addEventListener('change', () => {
                preferences[control.dataset.auditSetting] = control.type === 'checkbox' ? control.checked : control.value;
                applyPreferences();
                try {
                    localStorage.setItem(storageKey, JSON.stringify(preferences));
                } catch {
                    // La preferencia se mantiene durante esta visita.
                }
            });
        }

        window.addEventListener('storage', (event) => {
            if (event.key !== storageKey && event.key !== null) return;
            preferences = loadPreferences();
            applyPreferences();
            syncControls();
        });

        document.addEventListener('keydown', (event) => {
            if (event.defaultPrevented) return;
            if (event.key === 'Escape' && appearance?.open) {
                const returnFocus = appearance.contains(document.activeElement);
                appearance.open = false;
                if (returnFocus) appearance.querySelector('summary').focus();
                return;
            }
            if (!search || event.key.toLowerCase() !== 'k' || !(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) return;
            event.preventDefault();
            search.focus();
        });
    });
})();

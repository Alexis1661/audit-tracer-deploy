/**
 * registro.js — Validación del formulario de registro en cliente.
 * No realiza submit si hay errores de validación.
 */

(function () {
    'use strict';

    // ── Referencias al DOM ────────────────────────────────────
    const form          = document.getElementById('registro-form');
    const emailInput    = document.getElementById('email');
    const passInput     = document.getElementById('password');
    const confirmInput  = document.getElementById('confirmar_password');
    const rolSelect     = document.getElementById('rol');
    const submitBtn     = document.getElementById('submit-btn');

    const emailError    = document.getElementById('email-error');
    const passError     = document.getElementById('password-error');
    const confirmError  = document.getElementById('confirm-error');
    const rolError      = document.getElementById('rol-error');

    const togglePass    = document.getElementById('toggle-password');
    const toggleConfirm = document.getElementById('toggle-confirm');

    const passStrengthBar  = document.getElementById('pass-strength-bar');
    const passStrengthText = document.getElementById('pass-strength-text');

    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // ── Mostrar/Ocultar contraseña ────────────────────────────
    function buildToggle(btn, input) {
        if (!btn || !input) return;
        btn.addEventListener('click', function () {
            const isText = input.type === 'text';
            input.type = isText ? 'password' : 'text';
            btn.innerHTML = isText ? iconEye() : iconEyeOff();
        });
    }
    buildToggle(togglePass, passInput);
    buildToggle(toggleConfirm, confirmInput);

    // ── Indicador de fortaleza de contraseña ──────────────────
    function getStrength(pwd) {
        let score = 0;
        if (pwd.length >= 8)  score++;
        if (pwd.length >= 12) score++;
        if (/[A-Z]/.test(pwd)) score++;
        if (/[0-9]/.test(pwd)) score++;
        if (/[^A-Za-z0-9]/.test(pwd)) score++;
        return score; // 0-5
    }

    function updateStrengthIndicator(pwd) {
        if (!passStrengthBar || !passStrengthText) return;
        const score = getStrength(pwd);
        const levels = [
            { label: '',          color: '#D0DCE8', pct: '0%'   },
            { label: 'Muy débil', color: '#C0392B', pct: '20%'  },
            { label: 'Débil',     color: '#E67E22', pct: '40%'  },
            { label: 'Regular',   color: '#F1C40F', pct: '60%'  },
            { label: 'Fuerte',    color: '#27AE60', pct: '80%'  },
            { label: 'Muy fuerte',color: '#1A8C8C', pct: '100%' },
        ];
        const level = levels[score] || levels[0];
        passStrengthBar.style.width = pwd ? level.pct : '0%';
        passStrengthBar.style.backgroundColor = level.color;
        passStrengthText.textContent = pwd ? level.label : '';
        passStrengthText.style.color = level.color;
    }

    passInput.addEventListener('input', function () {
        updateStrengthIndicator(this.value);
        clearError(this, passError);
        // Re-validar confirm si ya tiene valor
        if (confirmInput.value) validateConfirm();
    });

    // ── Helpers ───────────────────────────────────────────────
    function setError(input, errorEl, msg) {
        input.classList.add('input-error');
        errorEl.textContent = msg;
        errorEl.classList.add('visible');
    }

    function clearError(input, errorEl) {
        input.classList.remove('input-error');
        errorEl.textContent = '';
        errorEl.classList.remove('visible');
    }

    // ── Funciones de validación individuales ──────────────────
    function validateEmail() {
        const val = emailInput.value.trim();
        if (!val) { setError(emailInput, emailError, 'El correo electrónico es requerido.'); return false; }
        if (!EMAIL_RE.test(val)) { setError(emailInput, emailError, 'Ingresa un correo electrónico válido.'); return false; }
        clearError(emailInput, emailError);
        return true;
    }

    function validatePassword() {
        const val = passInput.value;
        if (!val) { setError(passInput, passError, 'La contraseña es requerida.'); return false; }
        if (val.length < 8) { setError(passInput, passError, 'La contraseña debe tener mínimo 8 caracteres.'); return false; }
        clearError(passInput, passError);
        return true;
    }

    function validateConfirm() {
        const val = confirmInput.value;
        if (!val) { setError(confirmInput, confirmError, 'Debes confirmar la contraseña.'); return false; }
        if (val !== passInput.value) { setError(confirmInput, confirmError, 'Las contraseñas no coinciden.'); return false; }
        clearError(confirmInput, confirmError);
        return true;
    }

    function validateRol() {
        const val = rolSelect.value;
        if (!val) { setError(rolSelect, rolError, 'Selecciona un rol para continuar.'); return false; }
        clearError(rolSelect, rolError);
        return true;
    }

    // ── Validación on-blur ────────────────────────────────────
    emailInput.addEventListener('blur', validateEmail);
    passInput.addEventListener('blur', validatePassword);
    confirmInput.addEventListener('blur', validateConfirm);
    rolSelect.addEventListener('blur', validateRol);

    emailInput.addEventListener('input',   function () { clearError(this, emailError);   });
    confirmInput.addEventListener('input', function () { clearError(this, confirmError); });
    rolSelect.addEventListener('change',   function () { clearError(this, rolError);     });

    // ── Validación on-submit ──────────────────────────────────
    form.addEventListener('submit', function (e) {
        const ok = [
            validateEmail(),
            validatePassword(),
            validateConfirm(),
            validateRol(),
        ].every(Boolean);

        if (!ok) { e.preventDefault(); return; }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Creando cuenta...';
    });

    // ── Íconos SVG ────────────────────────────────────────────
    function iconEye() {
        return `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24"
                     fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>`;
    }

    function iconEyeOff() {
        return `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24"
                     fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8
                           a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4
                           c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07
                           a3 3 0 1 1-4.24-4.24"></path>
                  <line x1="1" y1="1" x2="23" y2="23"></line>
                </svg>`;
    }

})();

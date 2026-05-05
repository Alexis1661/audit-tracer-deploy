/**
 * login.js — Validación del formulario de login en cliente.
 * No realiza submit si hay errores de validación.
 */

(function () {
    'use strict';

    // ── Referencias al DOM ────────────────────────────────────
    const form        = document.getElementById('login-form');
    const emailInput  = document.getElementById('email');
    const passInput   = document.getElementById('password');
    const emailError  = document.getElementById('email-error');
    const passError   = document.getElementById('password-error');
    const submitBtn   = document.getElementById('submit-btn');
    const togglePass  = document.getElementById('toggle-password');

    // ── Regex de email simple ─────────────────────────────────
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // ── Mostrar/Ocultar contraseña ────────────────────────────
    if (togglePass) {
        togglePass.addEventListener('click', function () {
            const isText = passInput.type === 'text';
            passInput.type = isText ? 'password' : 'text';

            // Cambia el ícono del botón
            this.innerHTML = isText
                ? iconEye()
                : iconEyeOff();
        });
    }

    // ── Helpers de validación ─────────────────────────────────
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

    function validateEmail() {
        const val = emailInput.value.trim();
        if (!val) {
            setError(emailInput, emailError, 'El correo electrónico es requerido.');
            return false;
        }
        if (!EMAIL_RE.test(val)) {
            setError(emailInput, emailError, 'Ingresa un correo electrónico válido.');
            return false;
        }
        clearError(emailInput, emailError);
        return true;
    }

    function validatePassword() {
        const val = passInput.value;
        if (!val) {
            setError(passInput, passError, 'La contraseña es requerida.');
            return false;
        }
        clearError(passInput, passError);
        return true;
    }

    // ── Validación on-blur ────────────────────────────────────
    emailInput.addEventListener('blur', validateEmail);
    passInput.addEventListener('blur', validatePassword);

    // Limpiar error al empezar a escribir
    emailInput.addEventListener('input', function () { clearError(this, emailError); });
    passInput.addEventListener('input', function ()  { clearError(this, passError);  });

    // ── Validación on-submit ──────────────────────────────────
    form.addEventListener('submit', function (e) {
        const okEmail = validateEmail();
        const okPass  = validatePassword();

        if (!okEmail || !okPass) {
            e.preventDefault();
            return;
        }

        // Feedback visual durante el envío
        submitBtn.disabled = true;
        submitBtn.textContent = 'Verificando...';
    });

    // ── Íconos SVG inline ─────────────────────────────────────
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

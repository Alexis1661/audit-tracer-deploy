/**
 * animations.js — Lógica de Animaciones con Anime.js
 * Sistema de Auditoría de Trazabilidad
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Animación de entrada para el Layout Principal
    anime({
        targets: '#app-wrapper',
        opacity: [0, 1],
        translateY: [10, 0],
        duration: 800,
        easing: 'easeOutQuart'
    });

    // 2. Animación escalonada para elementos marcados como 'stagger-item'
    // Se usa comúnmente en tarjetas de métricas o filas de tablas
    const staggerItems = document.querySelectorAll('.stagger-item');
    if (staggerItems.length > 0) {
        anime({
            targets: '.stagger-item',
            opacity: [0, 1],
            translateY: [20, 0],
            delay: anime.stagger(100), // 100ms de retraso entre cada uno
            duration: 1000,
            easing: 'easeOutElastic(1, .8)'
        });
    }

    // 3. Animación para el Sidebar
    anime({
        targets: '.sidebar',
        translateX: [-260, 0],
        duration: 1000,
        easing: 'easeOutExpo',
        delay: 200
    });

    // 4. Efectos Hover Programáticos (opcional, ya hay CSS pero esto le da un toque premium)
    const cards = document.querySelectorAll('.metric-card, .card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            anime({
                targets: card,
                scale: 1.02,
                duration: 400,
                easing: 'easeOutCubic'
            });
        });
        card.addEventListener('mouseleave', () => {
            anime({
                targets: card,
                scale: 1,
                duration: 400,
                easing: 'easeOutCubic'
            });
        });
    });

    // 5. Animación de carga para botones al hacer submit
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const btn = form.querySelector('button[type="submit"]');
            if (btn) {
                // Pequeña animación de "click" o feedback
                anime({
                    targets: btn,
                    scale: [1, 0.95, 1],
                    duration: 300,
                    easing: 'easeInOutQuad'
                });
            }
        });
    });
});

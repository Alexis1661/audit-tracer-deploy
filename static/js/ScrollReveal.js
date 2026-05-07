/**
 * ScrollReveal.js — Vanilla JavaScript Version
 * Recrea el efecto de revelado de texto por palabras con scroll.
 */

class ScrollReveal {
    constructor(element, options = {}) {
        this.el = element;
        this.options = Object.assign({
            enableBlur: true,
            baseOpacity: 0.1,
            baseRotation: 3,
            blurStrength: 4,
            rotationEnd: 'bottom bottom',
            wordAnimationEnd: 'bottom bottom'
        }, options);

        this.init();
    }

    init() {
        this.splitText();
        this.setupAnimations();
    }

    splitText() {
        const text = this.el.innerText;
        this.el.innerHTML = '';
        const p = document.createElement('p');
        p.className = 'scroll-reveal-text';

        // Dividir por palabras manteniendo espacios
        const words = text.split(/(\s+)/);
        words.forEach(word => {
            if (word.match(/^\s+$/)) {
                p.appendChild(document.createTextNode(word));
            } else {
                const span = document.createElement('span');
                span.className = 'reveal-word';
                span.innerText = word;
                p.appendChild(span);
            }
        });

        this.el.appendChild(p);
    }

    setupAnimations() {
        // Rotación del contenedor
        gsap.fromTo(this.el, 
            { transformOrigin: '0% 50%', rotate: this.options.baseRotation },
            {
                ease: 'none',
                rotate: 0,
                scrollTrigger: {
                    trigger: this.el,
                    start: 'top bottom',
                    end: this.options.rotationEnd,
                    scrub: true
                }
            }
        );

        const wordElements = this.el.querySelectorAll('.reveal-word');

        // Opacidad de las palabras
        gsap.fromTo(wordElements,
            { opacity: this.options.baseOpacity },
            {
                ease: 'none',
                opacity: 1,
                stagger: 0.05,
                scrollTrigger: {
                    trigger: this.el,
                    start: 'top bottom-=20%',
                    end: this.options.wordAnimationEnd,
                    scrub: true
                }
            }
        );

        // Desenfoque de las palabras
        if (this.options.enableBlur) {
            gsap.fromTo(wordElements,
                { filter: `blur(${this.options.blurStrength}px)` },
                {
                    ease: 'none',
                    filter: 'blur(0px)',
                    stagger: 0.05,
                    scrollTrigger: {
                        trigger: this.el,
                        start: 'top bottom-=20%',
                        end: this.options.wordAnimationEnd,
                        scrub: true
                    }
                }
            );
        }
    }
}

window.ScrollReveal = ScrollReveal;

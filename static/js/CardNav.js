/**
 * CardNav.js — Vanilla JavaScript Version
 * Adaptado de la versión React con GSAP.
 */

class CardNav {
    constructor(container, options = {}) {
        this.container = container;
        this.options = Object.assign({
            items: [],
            logo: '',
            logoAlt: 'Logo',
            baseColor: '#fff',
            menuColor: '#000',
            buttonBgColor: '#111',
            buttonTextColor: '#fff',
            ease: 'power3.out'
        }, options);

        this.isExpanded = false;
        this.navRef = null;
        this.cardsRef = [];
        this.tl = null;

        this.init();
    }

    init() {
        this.render();
        this.navRef = this.container.querySelector('.card-nav');
        this.cardsRef = Array.from(this.container.querySelectorAll('.nav-card'));
        
        this.setupTimeline();
        this.setupEvents();
    }

    render() {
        const itemsHtml = this.options.items.slice(0, 3).map((item, idx) => `
            <div class="nav-card" style="background-color: ${item.bgColor}; color: ${item.textColor};">
                <div class="nav-card-label">${item.label}</div>
                <div class="nav-card-links">
                    ${(item.links || []).map(lnk => `
                        <a class="nav-card-link" href="${lnk.href || '#'}" aria-label="${lnk.ariaLabel || ''}">
                            <svg class="nav-card-link-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 17L17 7M17 7H7M17 7V17"/></svg>
                            ${lnk.label}
                        </a>
                    `).join('')}
                </div>
            </div>
        `).join('');

        this.container.innerHTML = `
            <div class="card-nav-container">
                <nav class="card-nav" style="background-color: ${this.options.baseColor}">
                    <div class="card-nav-top">
                        <div class="hamburger-menu" role="button" aria-label="Menu" tabindex="0" style="color: ${this.options.menuColor}">
                            <div class="hamburger-line"></div>
                            <div class="hamburger-line"></div>
                        </div>

                        <div class="logo-container">
                            <img src="${this.options.logo}" alt="${this.options.logoAlt}" class="logo">
                        </div>

                        <button type="button" class="card-nav-cta-button" style="background-color: ${this.options.buttonBgColor}; color: ${this.options.buttonTextColor}">
                            Get Started
                        </button>
                    </div>

                    <div class="card-nav-content" aria-hidden="true">
                        ${itemsHtml}
                    </div>
                </nav>
            </div>
        `;
    }

    calculateHeight() {
        const isMobile = window.matchMedia('(max-width: 768px)').matches;
        if (isMobile) {
            const contentEl = this.container.querySelector('.card-nav-content');
            const wasVisible = contentEl.style.visibility;
            
            contentEl.style.visibility = 'visible';
            contentEl.style.position = 'static';
            contentEl.style.height = 'auto';
            
            const contentHeight = contentEl.scrollHeight;
            
            contentEl.style.visibility = wasVisible;
            contentEl.style.position = 'absolute';
            contentEl.style.height = '';
            
            return 60 + contentHeight + 16;
        }
        return 260;
    }

    setupTimeline() {
        gsap.set(this.navRef, { height: 60, overflow: 'hidden' });
        gsap.set(this.cardsRef, { y: 50, opacity: 0 });

        this.tl = gsap.timeline({ paused: true });

        this.tl.to(this.navRef, {
            height: () => this.calculateHeight(),
            duration: 0.4,
            ease: this.options.ease
        });

        this.tl.to(this.cardsRef, { 
            y: 0, 
            opacity: 1, 
            duration: 0.4, 
            ease: this.options.ease, 
            stagger: 0.08 
        }, '-=0.1');
    }

    setupEvents() {
        const hamburger = this.container.querySelector('.hamburger-menu');
        hamburger.addEventListener('click', () => this.toggleMenu());

        window.addEventListener('resize', () => {
            if (this.isExpanded) {
                gsap.set(this.navRef, { height: this.calculateHeight() });
            }
        });
    }

    toggleMenu() {
        const hamburger = this.container.querySelector('.hamburger-menu');
        if (!this.isExpanded) {
            hamburger.classList.add('open');
            this.isExpanded = true;
            this.tl.play();
        } else {
            hamburger.classList.remove('open');
            this.tl.reverse().eventCallback('onReverseComplete', () => {
                this.isExpanded = false;
            });
        }
    }
}

window.CardNav = CardNav;

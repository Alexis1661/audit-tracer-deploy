/**
 * DecryptedText.js — Vanilla JavaScript Version
 * Recrea el efecto de texto desencriptado proporcionado en React.
 */

class DecryptedText {
    constructor(element, options = {}) {
        this.el = element;
        this.originalText = element.getAttribute('data-text') || element.innerText;
        this.options = Object.assign({
            speed: 50,
            delay: 0,
            maxIterations: 10,
            sequential: false,
            revealDirection: 'start',
            useOriginalCharsOnly: false,
            characters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+',
            animateOn: 'hover', // 'hover', 'view', 'click'
            clickMode: 'once'
        }, options);

        this.displayText = this.originalText;
        this.isAnimating = false;
        this.revealedIndices = new Set();
        this.hasAnimated = false;
        this.interval = null;

        this.availableChars = this.options.useOriginalCharsOnly
            ? Array.from(new Set(this.originalText.split(''))).filter(char => char !== ' ')
            : this.options.characters.split('');

        this.init();
    }

    init() {
        if (this.options.animateOn === 'hover') {
            this.el.addEventListener('mouseenter', () => this.triggerDecrypt());
            this.el.addEventListener('mouseleave', () => this.resetToPlainText());
        } else if (this.options.animateOn === 'view') {
            this.setupIntersectionObserver();
        } else if (this.options.animateOn === 'click') {
            this.el.style.cursor = 'pointer';
            this.el.addEventListener('click', () => this.handleClick());
            this.encryptInstantly();
        }
    }

    setupIntersectionObserver() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting && !this.hasAnimated) {
                    this.triggerDecrypt();
                    this.hasAnimated = true;
                }
            });
        }, { threshold: 0.1 });
        observer.observe(this.el);
    }

    encryptInstantly() {
        this.revealedIndices.clear();
        this.el.innerText = this.shuffleText(this.originalText, this.revealedIndices);
    }

    shuffleText(text, currentRevealed) {
        return text.split('').map((char, i) => {
            if (char === ' ' || char === '\n') return char;
            if (currentRevealed.has(i)) return text[i];
            return this.availableChars[Math.floor(Math.random() * this.availableChars.length)];
        }).join('');
    }

    triggerDecrypt() {
        if (this.isAnimating) return;
        this.isAnimating = true;
        this.revealedIndices.clear();
        
        setTimeout(() => {
            let currentIteration = 0;
            const textLength = this.originalText.length;

            this.interval = setInterval(() => {
                if (this.options.sequential) {
                    if (this.revealedIndices.size < textLength) {
                        const nextIndex = this.getNextIndex();
                        this.revealedIndices.add(nextIndex);
                        this.el.innerText = this.shuffleText(this.originalText, this.revealedIndices);
                    } else {
                        this.stopAnimation();
                    }
                } else {
                    this.el.innerText = this.shuffleText(this.originalText, this.revealedIndices);
                    currentIteration++;
                    if (currentIteration >= this.options.maxIterations) {
                        this.stopAnimation();
                    }
                }
            }, this.options.speed);
        }, this.options.delay);
    }

    getNextIndex() {
        const len = this.originalText.length;
        if (this.options.revealDirection === 'start') {
            return this.revealedIndices.size;
        } else if (this.options.revealDirection === 'end') {
            return len - 1 - this.revealedIndices.size;
        } else {
            // center (simplificado)
            const middle = Math.floor(len / 2);
            const offset = Math.floor(this.revealedIndices.size / 2);
            const next = this.revealedIndices.size % 2 === 0 ? middle + offset : middle - offset - 1;
            return (next >= 0 && next < len) ? next : this.revealedIndices.size;
        }
    }

    stopAnimation() {
        clearInterval(this.interval);
        this.isAnimating = false;
        this.el.innerText = this.originalText;
    }

    resetToPlainText() {
        clearInterval(this.interval);
        this.isAnimating = false;
        this.el.innerText = this.originalText;
    }

    handleClick() {
        if (this.options.clickMode === 'once' && this.hasAnimated) return;
        this.triggerDecrypt();
        this.hasAnimated = true;
    }
}

window.DecryptedText = DecryptedText;

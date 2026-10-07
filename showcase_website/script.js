/**
 * Cyber Rakshak IDS - 2026 Interactive Showcase & Animation Engine
 * Autonomous Edge AI Intrusion Detection & Hardware Security Experience
 */

(function () {
    'use strict';

    // ========================================================
    // 1. DEFAULT LIGHT THEME ENFORCEMENT
    // ========================================================
    try {
        localStorage.removeItem('cyberrakshak_theme');
    } catch (e) {}
    document.documentElement.setAttribute('data-theme', 'light');

    // ========================================================
    // 2. NAVBAR SCROLL ELEVATION & SCROLLSPY
    // ========================================================
    const topNav = document.getElementById('topNav');
    const navLinks = document.querySelectorAll('.nav-menu-center .nav-pill-link');
    const sections = ['hero', 'services', 'hardware', 'interactive-lab', 'pricing', 'faq'];

    function handleScroll() {
        const scrollY = window.scrollY;

        // Navbar shrink & glass elevation
        if (topNav) {
            if (scrollY > 20) {
                topNav.classList.add('scrolled');
            } else {
                topNav.classList.remove('scrolled');
            }
        }

        // Dynamic Scrollspy highlight
        let currentSectionId = 'hero';
        sections.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                const top = el.offsetTop - 120;
                const height = el.offsetHeight;
                if (scrollY >= top && scrollY < top + height) {
                    currentSectionId = id;
                }
            }
        });

        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href === '#' + currentSectionId) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });
    }

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();

    // ========================================================
    // 3. STATS COUNT-UP NUMERICAL ANIMATION
    // ========================================================
    let statsAnimated = false;

    function animateCountUp() {
        if (statsAnimated) return;
        const statElements = document.querySelectorAll('.counter-stat');

        statElements.forEach(el => {
            const target = parseFloat(el.getAttribute('data-target') || '0');
            const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
            const prefix = el.getAttribute('data-prefix') || '';
            const suffix = el.getAttribute('data-suffix') || '';
            const duration = 1800; // ms
            const startTime = performance.now();

            function updateCounter(currentTime) {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                // EaseOutQuad easing
                const easeProgress = 1 - (1 - progress) * (1 - progress);
                const currentVal = (target * easeProgress).toFixed(decimals);

                el.textContent = `${prefix}${currentVal}${suffix}`;

                if (progress < 1) {
                    requestAnimationFrame(updateCounter);
                } else {
                    el.textContent = `${prefix}${target.toFixed(decimals)}${suffix}`;
                }
            }

            requestAnimationFrame(updateCounter);
        });

        statsAnimated = true;
    }

    // ========================================================
    // 4. SCROLL REVEAL INTERSECTION OBSERVER
    // ========================================================
    const revealObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');

                // Trigger count-up if banner is intersecting
                if (entry.target.classList.contains('hero-bottom-stats-banner') || entry.target.querySelector('.counter-stat')) {
                    animateCountUp();
                }

                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.15 });

    document.querySelectorAll('.reveal-on-scroll, .services-grid-6 .service-box-clean, .modes-tri-grid .mode-card-item, .pricing-cards-grid .clean-price-card').forEach(el => {
        el.classList.add('reveal-on-scroll');
        revealObserver.observe(el);
    });

    // ========================================================
    // 5. HERO HARDWARE 3D MOUSE PARALLAX TILT
    // ========================================================
    const heroStage = document.getElementById('heroHardwareStage');
    const heroSection = document.getElementById('hero');
    const parallaxElements = document.querySelectorAll('[data-parallax]');

    if (heroSection && heroStage) {
        heroSection.addEventListener('mousemove', (e) => {
            const rect = heroSection.getBoundingClientRect();
            const mouseX = e.clientX - rect.left - rect.width / 2;
            const mouseY = e.clientY - rect.top - rect.height / 2;

            const tiltX = (mouseY / (rect.height / 2)) * -6; // max 6 deg
            const tiltY = (mouseX / (rect.width / 2)) * 6;

            const devWrapper = document.getElementById('heroDeviceWrapper');
            if (devWrapper) {
                devWrapper.style.transform = `perspective(1000px) rotateX(${tiltX.toFixed(2)}deg) rotateY(${tiltY.toFixed(2)}deg)`;
            }

            parallaxElements.forEach(el => {
                const depth = parseFloat(el.getAttribute('data-parallax') || '0.02');
                const transX = mouseX * depth;
                const transY = mouseY * depth;
                el.style.transform = `translate3d(${transX.toFixed(1)}px, ${transY.toFixed(1)}px, 0)`;
            });
        }, { passive: true });

        heroSection.addEventListener('mouseleave', () => {
            const devWrapper = document.getElementById('heroDeviceWrapper');
            if (devWrapper) {
                devWrapper.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg)';
                devWrapper.style.transition = 'transform 0.6s ease';
            }
            parallaxElements.forEach(el => {
                el.style.transform = 'translate3d(0, 0, 0)';
                el.style.transition = 'transform 0.6s ease';
            });
        });
    }

    // ========================================================
    // 6. CONTINUOUS NETWORK PACKET JOURNEY & AI DECISION LOOP
    // ========================================================
    const stepBadgeText = document.getElementById('coreLiveStepText');
    const hudDpi = document.getElementById('hudDpiStage');
    const hudAi = document.getElementById('hudAiInference');
    const hudPacket = document.getElementById('hudPacketStatus');
    const hudMitigation = document.getElementById('hudMitigationStatus');

    const pipelineStages = [
        {
            step: '1. Traffic Captured',
            dpi: 'Raw Socket Ingress • 84 Features',
            ai: 'Kernel Buffer Stream • Active',
            packet: 'Ingress: 192.168.1.108 (HTTPS)',
            mitigation: 'In-Line Transparent Bridge'
        },
        {
            step: '2. 84 Features Extracted',
            dpi: 'IAT & Entropy Matrix Computed',
            ai: 'Tensor Normalization • Complete',
            packet: 'Flow Duration: 42ms • Flags: SYN-ACK',
            mitigation: '0.04ms Parsing Window'
        },
        {
            step: '3. Local AI Inference',
            dpi: 'Edge XGBoost Classifier Engine',
            ai: 'Probability Score: 0.001 (Safe)',
            packet: 'Zero Malicious Signatures Found',
            mitigation: 'Sub-0.08ms Execution'
        },
        {
            step: '4. Decision: Allowed',
            dpi: 'Fast-Path Kernel Forwarding',
            ai: 'Session State: Verified Safe',
            packet: 'Forwarded to Protected Endpoints',
            mitigation: 'Zero Jitter • 100 Mbps Line-Rate'
        }
    ];

    let currentPipelineIndex = 0;

    function runPipelineCycle() {
        if (!stepBadgeText) return;
        const current = pipelineStages[currentPipelineIndex];

        stepBadgeText.textContent = current.step;
        if (hudDpi) hudDpi.textContent = current.dpi;
        if (hudAi) hudAi.textContent = current.ai;
        if (hudPacket) hudPacket.textContent = current.packet;
        if (hudMitigation) hudMitigation.textContent = current.mitigation;

        currentPipelineIndex = (currentPipelineIndex + 1) % pipelineStages.length;
    }

    setInterval(runPipelineCycle, 2400);

    // ========================================================
    // 7. DYNAMIC AIR-GAP THREAT ISOLATION SIMULATOR
    // ========================================================
    window.triggerAirGapSim = function () {
        const btn = document.getElementById('btnSimAirGap');
        const threatNode = document.getElementById('threatDeviceNode');
        const barrierBeam = document.getElementById('barrierBeam');
        const barrierAction = document.getElementById('barrierAction');
        const statusText = document.getElementById('airgapStatusText');
        const log = document.getElementById('airgapSimLog');

        if (btn) btn.disabled = true;

        // Stage 1: Threat Detected
        if (threatNode) threatNode.classList.add('active-threat');
        if (barrierBeam) barrierBeam.classList.add('threat-blocked');
        if (barrierAction) {
            barrierAction.textContent = 'BLOCKING & ISOLATING';
            barrierAction.style.color = '#ef4444';
        }
        if (statusText) {
            statusText.textContent = 'LATERAL ATTACK DROPPED (0.07ms)';
            statusText.style.color = '#ef4444';
        }
        if (log) {
            log.innerHTML = '<span class="text-ruby font-mono" style="font-weight:700;"><i class="fa-solid fa-ban"></i> MALICIOUS LATERAL SCAN BLOCKED:</span> Malicious probe from IoT Plug quarantined. Enterprise VLAN 10 protected.';
        }

        // Stage 2: Restore Normal after 2.8s
        setTimeout(() => {
            if (threatNode) threatNode.classList.remove('active-threat');
            if (barrierBeam) barrierBeam.classList.remove('threat-blocked');
            if (barrierAction) {
                barrierAction.textContent = 'Pass-Through Filtering';
                barrierAction.style.color = '#10b981';
            }
            if (statusText) {
                statusText.textContent = 'MICRO-SEGMENTATION ENFORCED';
                statusText.style.color = '#10b981';
            }
            if (log) {
                log.innerHTML = '<span class="text-green font-mono">&bull; Status:</span> All IoT device telemetry contained within isolated VLAN segment.';
            }
            if (btn) btn.disabled = false;
        }, 2800);
    };

    // ========================================================
    // 8. SCENARIO TABS CONTROLLER
    // ========================================================
    window.switchScenario = function (id, btn) {
        document.querySelectorAll('.scenario-tab-btn').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
        document.querySelectorAll('.scenario-content-pane').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('pane-' + id);
        if (target) target.classList.add('active');
    };

    // ========================================================
    // 9. FAQ ACCORDION
    // ========================================================
    window.toggleFaq = function (btn) {
        const item = btn.parentElement;
        const isActive = item.classList.contains('active');
        document.querySelectorAll('.faq-item').forEach(i => i.classList.remove('active'));
        if (!isActive) item.classList.add('active');
    };

})();


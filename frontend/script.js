let data = null;

async function scanWebsite() {

    try {

        const urlInput =
            document.getElementById('urlInput');

        const url =
            urlInput.value.trim();

        if (!url) {

            alert('Please enter a website URL');

            return;
        }

        // Validate URL
        if (!isValidUrl(url)) {

            alert(
                'Please enter valid URL'
            );

            return;
        }

        // Reset collapsible panels
        document.querySelectorAll('.card-expanded-details').forEach(panel => {
            panel.classList.remove('open');
            panel.style.maxHeight = '0px';
        });
        document.querySelectorAll('.expand-btn').forEach(btn => {
            btn.classList.remove('active');
            const span = btn.querySelector('span');
            if (span) span.textContent = 'View Full Details';
        });

        // Show loading
        const scanBtn =
            document.querySelector('.scan-btn');

        const originalText =
            scanBtn.innerHTML;

        scanBtn.innerHTML =
            '<i class="fas fa-spinner fa-spin"></i> Scanning...';

        scanBtn.disabled = true;

        // Backend API
        const apiUrl = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || !window.location.hostname
            ? 'http://localhost:8000/scan'
            : 'https://website-security-scanner-2-1.onrender.com/scan';
        
        const response =
            await fetch(
                apiUrl,
                {
                    method: 'POST',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body: JSON.stringify({
                        url
                    })
                }
            );

if (!response.ok) {
    throw new Error(`Backend Error: ${response.status}`);
}

data = await response.json();

console.log("API Response:", data);
        console.log(data);

        // Show results
        document.getElementById(
            'heroSection'
        ).style.display = 'none';

        document.getElementById(
            'resultsSection'
        ).style.display = 'block';

        // Show AI Chatbot floating widget
        const chatWidget = document.getElementById('aiChatbotWidget');
        if (chatWidget) {
            chatWidget.style.display = 'block';
        }

        // =========================
        // WEBSITE INFO
        // =========================

        document.getElementById(
            'resultWebsite'
        ).textContent =
            new URL(url).hostname;

        document.getElementById(
            'resultUrl'
        ).textContent =
            url;

        document.getElementById(
            'resultDate'
        ).textContent =
            new Date().toLocaleString();

        // =========================
        // HUMAN SUMMARY & QUICK METADATA
        // =========================
        document.getElementById('humanSummaryText').textContent =
            data.summary.human_summary || "No summary generated.";

        const info = data.website_info || {};
        document.getElementById('metaIp').textContent = info.ip_address || "--";
        document.getElementById('metaLocation').textContent = info.country || "--";
        document.getElementById('metaIsp').textContent = info.isp || "--";
        document.getElementById('metaCreated').textContent = info.created || "--";
        document.getElementById('metaRegistrar').textContent = info.registrar || "--";
        document.getElementById('metaConnectionType').textContent = 
            data.scans?.ssl?.ssl_enabled ? 'Secure (HTTPS)' : 'Insecure (HTTP)';

        // =========================
        // SCORE
        // =========================

        const score =
            data.summary.security_score;

        document.getElementById(
            'scoreValue'
        ).textContent =
            score;

        const scoreStatus = document.getElementById('scoreStatus');
        scoreStatus.textContent = data.summary.risk_level;
        scoreStatus.classList.remove('risk-low', 'risk-medium', 'risk-high');
        const riskVal = (data.summary.risk_level || '').toUpperCase();
        if (riskVal === 'HIGH' || riskVal.includes('HIGH')) {
            scoreStatus.classList.add('risk-high');
        } else if (riskVal === 'MEDIUM' || riskVal.includes('MEDIUM')) {
            scoreStatus.classList.add('risk-medium');
        } else {
            scoreStatus.classList.add('risk-low');
        }

        // Progress circle
        const progressCircle =
            document.getElementById(
                'progressCircle'
            );

        const circumference =
            282.7;

        const offset =
            circumference -
            (score / 100) *
            circumference;

        progressCircle.style
            .strokeDashoffset = offset;

        // =========================
        // SSL
        // =========================

        document.getElementById(
            'sslStatus'
        ).textContent =
            data.scans.ssl.ssl_enabled
                ? 'Enabled'
                : 'Disabled';

        document.getElementById(
            'sslProtocol'
        ).textContent =
            data.scans.ssl.protocol_version || 'None';

        document.getElementById(
            'sslExpires'
        ).textContent =
            data.scans.ssl.expiry_date || '-';

        document.getElementById(
            'sslCert'
        ).textContent =
            data.scans.ssl.is_self_signed 
                ? 'Self-Signed (Warning)' 
                : (data.scans.ssl.success ? 'Valid' : 'Invalid');

        // =========================
        // PORTS
        // =========================

        const openPorts =
            data.scans.ports.open_ports || [];

        document.getElementById(
            'runningServices'
        ).textContent =
            openPorts.length > 0
                ? openPorts
                    .map(port => port.service)
                    .join(', ')
                : 'None';

        
        document.getElementById(
            'openPorts'
        ).textContent =
            (data.scans.ports.open_ports || []).length;

        document.getElementById(
            'vulnerablePorts'
        ).textContent =
            (data.scans.ports.vulnerable_ports || []).length;

        // =========================
        // PERFORMANCE
        // =========================

        const perf = data.scans?.performance;
        if (perf && perf.success !== false) {
            document.getElementById('performanceScore').textContent = 
                perf.performance_score !== undefined && perf.performance_score !== null 
                    ? Math.round(perf.performance_score) 
                    : '--';
            document.getElementById('fcp').textContent = perf.first_contentful_paint || '--';
            document.getElementById('lcp').textContent = perf.largest_contentful_paint || '--';
            document.getElementById('speedIndex').textContent = perf.speed_index || '--';
            document.getElementById('pageLoadTime').textContent = perf.page_load_time || '--';
            document.getElementById('ttfb').textContent = perf.ttfb || '--';
            document.getElementById('mobileFriendly').textContent = perf.mobile_friendly || '--';
        } else {
            document.getElementById('performanceScore').textContent = '--';
            document.getElementById('fcp').textContent = '--';
            document.getElementById('lcp').textContent = '--';
            document.getElementById('speedIndex').textContent = '--';
            document.getElementById('pageLoadTime').textContent = '--';
            document.getElementById('ttfb').textContent = '--';
            document.getElementById('mobileFriendly').textContent = '--';
        }


        // =========================
// DNS INFORMATION
// =========================

document.getElementById("dnsIp").textContent =
    data.scans?.dns?.ip_address || "-";

document.getElementById("dnsA").textContent =
    (data.scans?.dns?.A?.length)
        ? data.scans.dns.A.join(", ")
        : "None";

document.getElementById("dnsMX").textContent =
    (data.scans?.dns?.MX?.length)
        ? data.scans.dns.MX.join(", ")
        : "None";

document.getElementById("dnsNS").textContent =
    (data.scans?.dns?.NS?.length)
        ? data.scans.dns.NS.join(", ")
        : "None";

document.getElementById("dnsTXT").textContent =
    (data.scans?.dns?.TXT?.length)
        ? data.scans.dns.TXT.slice(0, 3).join(", ")
        : "None";


        // =========================
// TECHNOLOGY DETECTOR
// =========================

const technologyContainer =
    document.getElementById("technologyContainer");

technologyContainer.innerHTML = "";

const technology =
    data.scans.technology;

if (
    technology.success &&
    technology.technologies &&
    Object.keys(technology.technologies).length > 0
){

    Object.entries(technology.technologies).forEach(([key,value])=>{

        const item =
            document.createElement("div");

        item.className="tech-item";

        const title =
            document.createElement("div");

        title.className="tech-title";

        title.textContent =
            key
            .replace(/-/g," ")
            .replace(/\b\w/g,l=>l.toUpperCase());

        const techValue =
            document.createElement("div");

        techValue.className="tech-value";

        techValue.textContent =
            Array.isArray(value)
            ? value.join(", ")
            : value;

        item.appendChild(title);

        item.appendChild(techValue);

        technologyContainer.appendChild(item);

    });

}
else{

    technologyContainer.innerHTML=
    `
        <div class="technology-loading">
            No technology detected.
        </div>
    `;

}




        // =========================
        // SEO
        // =========================

        document.getElementById(
            'seoTitle'
        ).textContent =
            data.scans.seo.title || 'Not Found';

        document.getElementById(
            'seoMetaDescription'
        ).textContent =
            data.scans.seo.meta_description
                ? 'Present'
                : 'Missing';

        document.getElementById(
            'seoMissingAltImages'
        ).textContent =
            data.scans.seo.missing_alt_images;

        document.getElementById(
            'headingCount'
        ).textContent =
            data.scans.seo.h1_count;

        document.getElementById(
            'missingAlt'
        ).textContent =
            data.scans.seo.missing_alt_images;

        document.getElementById(
            'metaTags'
        ).textContent =
            data.scans.seo.meta_description
                ? 'Available'
                : 'Missing';

        // =========================
        // RECOMMENDATIONS
        // =========================

        const recommendations =
            data.summary
                .recommendations;
        
        const recommendationList =
            document.getElementById(
                "recommendationsList"
            );

        recommendationList.innerHTML = "";

        recommendations.forEach(rec => {

            const li =
                document.createElement("li");

            li.textContent = rec;

            recommendationList.appendChild(li);
        });

        console.log(
            recommendations
        );

        // =========================
        // POPULATE DETAILED PANELS
        // =========================
        populateSslDetails(data.scans.ssl);
        populateSeoDetails(data.scans.seo);
        populatePerformanceDetails(data.scans.performance);
        populateDnsDetails(data.scans.dns);
        populateTechnologyDetails(data.scans.technology);
        populatePortsDetails(data.scans.ports);
        populateHeadersDetails(data.scans.headers);

        // Reset button
        scanBtn.innerHTML =
            originalText;

        scanBtn.disabled = false;

        // Scroll
        setTimeout(() => {

            document.getElementById(
                'resultsSection'
            ).scrollIntoView({
                behavior: 'smooth'
            });

        }, 500);

    } catch(error) {

        console.log(error);

        alert('Scan failed');

        const scanBtn =
            document.querySelector('.scan-btn');

        scanBtn.innerHTML =
            '<i class="fas fa-search"></i> Scan Now';

        scanBtn.disabled = false;
    }
}

// Update progress bars
function updateProgressBar(id, percentage) {

    const value =
        document.getElementById(id);

    if (value) {
        value.textContent = percentage + "%";
    }

    let fillId = "";

    if (id === "metaTags") {
        fillId = "metaTagsFill";
    }

    else if (id === "headingCount") {
        fillId = "headingFill";
    }

    else if (id === "missingAlt") {
        fillId = "accessibilityFill";
    }

    const fill =
        document.getElementById(fillId);

    if (fill) {

        fill.style.width =
            percentage + "%";
    }
}

// Back to Scanner
function backToScanner() {
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('heroSection').style.display = 'block';
    document.getElementById('urlInput').value = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Download Report (TXT)
function downloadReport() {
    const website = document.getElementById('resultWebsite').textContent;
    const url = document.getElementById('resultUrl').textContent;
    const score = document.getElementById('scoreValue').textContent;
    const status = document.getElementById('scoreStatus').textContent;
    const date = document.getElementById('resultDate').textContent;
    const humanSummary = document.getElementById('humanSummaryText').textContent;

    const metaIp = document.getElementById('metaIp').textContent;
    const metaLoc = document.getElementById('metaLocation').textContent;
    const metaIsp = document.getElementById('metaIsp').textContent;
    const metaCreated = document.getElementById('metaCreated').textContent;
    const metaReg = document.getElementById('metaRegistrar').textContent;
    const metaConn = document.getElementById('metaConnectionType').textContent;

    const reportContent = `
WEBSITE SECURITY SCAN REPORT
========================================

Website: ${website || '-'}
URL: ${url || '-'}
Scan Date: ${date || new Date().toLocaleString()}

SECURITY SCORE: ${score}/100 (${status} Risk)

HUMAN-FRIENDLY SUMMARY
========================================
${humanSummary || 'No summary available.'}

WEBSITE INFO & DETAILS
========================================
- IP Address: ${metaIp || '-'}
- Hosting Location: ${metaLoc || '-'}
- Internet Provider (ISP): ${metaIsp || '-'}
- Domain Created: ${metaCreated || '-'}
- Domain Registrar: ${metaReg || '-'}
- Connection Security: ${metaConn || '-'}

========================================
DETAILED SECURITY METRICS
========================================

SSL/TLS CERTIFICATE:
- Status: ${document.getElementById('sslStatus').textContent || '-'}
- Protocol: ${document.getElementById('sslProtocol').textContent || '-'}
- Expires: ${document.getElementById('sslExpires').textContent || '-'}

PORT SCAN:
- Open Ports: ${document.getElementById('openPorts').textContent || '0'}
- Vulnerable: ${document.getElementById('vulnerablePorts').textContent || '0'}
- Services: ${document.getElementById('runningServices').textContent || 'None'}

DNS INFORMATION:
- IP Address: ${document.getElementById('dnsIp').textContent || '-'}
- A Records: ${document.getElementById('dnsA').textContent || 'None'}
- MX Records: ${document.getElementById('dnsMX').textContent || 'None'}
- NS Records: ${document.getElementById('dnsNS').textContent || 'None'}
- TXT Records: ${document.getElementById('dnsTXT').textContent || 'None'}

PERFORMANCE:
- Performance Score: ${document.getElementById('performanceScore').textContent || '-'}
- First Contentful Paint: ${document.getElementById('fcp').textContent || '-'}
- Largest Contentful Paint: ${document.getElementById('lcp').textContent || '-'}
- Speed Index: ${document.getElementById('speedIndex').textContent || '-'}

SEO ANALYSIS:
- Title: ${document.getElementById('seoTitle').textContent || 'Missing'}
- Meta Description: ${document.getElementById('seoMetaDescription').textContent || 'Missing'}
- H1 Count: ${document.getElementById('headingCount').textContent || '0'}
- Missing Alt Images: ${document.getElementById('missingAlt').textContent || '0'}

RECOMMENDATIONS:
${Array.from(document.querySelectorAll('#recommendationsList li')).map(li => `- ${li.textContent}`).join('\n') || 'None'}

Generated by JobJockey Security Scanner
${new Date().toLocaleString()}
    `;

    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(reportContent));
    element.setAttribute('download', `security-report-${website}-${Date.now()}.txt`);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// Validate URL
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Add animation on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.animation = 'fadeInUp 0.6s ease forwards';
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe all cards and sections
document.querySelectorAll('.detector-card, .step-card, .score-card, .risk-card, .value-card, .feature-card, .pricing-card, .result-card').forEach(el => {
    observer.observe(el);
});

// Add animation keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-30px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }

    @keyframes floatIn {
        from {
            opacity: 0;
            transform: translateY(20px) scale(0.95);
        }
        to {
            opacity: 1;
            transform: translateY(0) scale(1);
        }
    }

    @keyframes glow {
        0%, 100% {
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        50% {
            box-shadow: 0 0 40px rgba(0, 212, 255, 0.5);
        }
    }

    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }

    .fa-spinner {
        animation: spin 1s linear infinite;
    }

    .hero h1 {
        animation: slideDown 0.8s ease;
    }
`;
document.head.appendChild(style);

// Navbar scroll effect
let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', function() {
    let scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    if (scrollTop > 100) {
        navbar.style.boxShadow = '0 5px 20px rgba(0, 0, 0, 0.3)';
    } else {
        navbar.style.boxShadow = 'none';
    }
    
    lastScrollTop = scrollTop <= 0 ? 0 : scrollTop;
});

// Form validation for email signup (if forms are added)
document.addEventListener('DOMContentLoaded', function() {
    // Initialize any buttons or forms that need interaction
    const signupBtn = document.querySelector('.signup-btn');
    if (signupBtn && signupBtn.href === '#') {
        signupBtn.addEventListener('click', function(e) {
            e.preventDefault();
            alert('Sign up feature would be implemented here');
        });
    }

    const loginBtn = document.querySelector('.login-btn');
    if (loginBtn && loginBtn.href === '#') {
        loginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            alert('Login feature would be implemented here');
        });
    }
});

// Pricing plan selection
document.addEventListener('DOMContentLoaded', function() {
    const pricingBtns = document.querySelectorAll('.pricing-btn');
    pricingBtns.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const planName = this.parentElement.querySelector('h3').textContent;
            alert(`You selected the ${planName} plan. Proceeding to checkout...`);
        });
    });
});

// Add hover effects to table rows
const tableRows = document.querySelectorAll('.scan-table tbody tr');
tableRows.forEach(row => {
    row.addEventListener('click', function() {
        const website = this.querySelector('td:first-child').textContent;
        console.log('Selected website:', website);
    });
});

// Mobile menu toggle (if needed in future)
function toggleMobileMenu() {
    const navMenu = document.querySelector('.nav-menu');
    navMenu.style.display = navMenu.style.display === 'flex' ? 'none' : 'flex';
}

// Debounce function for window resize
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Handle window resize for responsive adjustments
const handleResize = debounce(function() {
    console.log('Window resized');
}, 250);

window.addEventListener('resize', handleResize);

// Auto-format URL input
document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('blur', function() {
            let value = this.value.trim();
            if (value && !value.startsWith('http')) {
                value = 'https://' + value;
                this.value = value;
            }
        });
    }
});

// Add keyboard shortcut for scan (Enter key)
document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                scanWebsite();
            }
        });
    }
});

// Analytics tracking (placeholder)
function trackEvent(eventName, eventData) {
    console.log('Event tracked:', {
        event: eventName,
        data: eventData,
        timestamp: new Date().toISOString()
    });
    // In production, this would send data to an analytics service
}

// Track page views
trackEvent('page_view', {
    page: 'home',
    url: window.location.href
});

// Track button clicks
document.querySelectorAll('button, a').forEach(element => {
    element.addEventListener('click', function() {
        trackEvent('button_click', {
            text: this.textContent.trim(),
            type: this.tagName.toLowerCase()
        });
    });
});


// ===========================
// FAQ Toggle Functionality
// ===========================
function toggleFAQ(element) {
    // Close all other FAQ items
    document.querySelectorAll('.faq-question').forEach(item => {
        if (item !== element) {
            item.classList.remove('active');
            item.nextElementSibling.classList.remove('active');
        }
    });

    // Toggle current FAQ item
    element.classList.toggle('active');
    element.nextElementSibling.classList.toggle('active');
}

// =========================
// SEO MODAL FUNCTIONS
// =========================

// Close Modal
function closeDetailModal() {
    const modal = document.getElementById('detailModal');
    modal.style.display = 'none';
}

// Show Meta Description Details
function showMetaDescriptionDetails() {
    if (!data || !data.scans || !data.scans.seo) {
        alert('No SEO data available');
        return;
    }

    const seoData = data.scans.seo;
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    // Set title
    modalTitle.innerHTML = '<i class="fas fa-file-alt"></i> Meta Description Details';

    // Build content
    let content = '';

    if (seoData.meta_description) {
        content = `
            <div class="details-list">
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-check-circle"></i> Meta Description Found
                    </div>
                    <div class="detail-item-content">
                        ${seoData.meta_description}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-ruler"></i> Length
                    </div>
                    <div class="detail-item-content">
                        ${seoData.meta_description.length} characters
                        <br/>
                        <small style="color: var(--text-secondary);">
                            ${seoData.meta_description.length >= 120 && seoData.meta_description.length <= 160 
                                ? '✅ Optimal length (120-160 chars)' 
                                : '⚠️ Consider adjusting to 120-160 characters'}
                        </small>
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-lightbulb"></i> SEO Tip
                    </div>
                    <div class="detail-item-content">
                        A good meta description should be between 120-160 characters and include your main keywords. This text appears in search engine results and helps users decide whether to click your link.
                    </div>
                </div>
            </div>
        `;
    } else {
        content = `
            <div class="empty-state">
                <i class="fas fa-times-circle"></i>
                <h3 style="color: var(--danger);">No Meta Description Found</h3>
                <p>This page is missing a meta description. This is important for SEO and search engine visibility.</p>
                <p style="margin-top: 1.5rem; font-size: 0.9rem;">
                    <strong>Recommendation:</strong> Add a meta description tag to your HTML:
                </p>
                <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; margin-top: 1rem; text-align: left;">
                    <code style="color: var(--primary);">&lt;meta name="description" content="Your description here" /&gt;</code>
                </div>
            </div>
        `;
    }

    modalBody.innerHTML = content;
    modal.style.display = 'flex';
}

// Show H1 Tags Details
function showH1TagsDetails() {
    if (!data || !data.scans || !data.scans.seo) {
        alert('No SEO data available');
        return;
    }

    const seoData = data.scans.seo;
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    // Set title
    modalTitle.innerHTML = `<i class="fas fa-heading"></i> H1 Tags Details`;

    // Build content
    let content = '';

    if (seoData.h1_tags && seoData.h1_tags.length > 0) {
        const h1List = seoData.h1_tags.map((h1, index) => `
            <div class="detail-item">
                <div class="detail-item-label">
                    <i class="fas fa-heading"></i> H1 Tag #${index + 1}
                </div>
                <div class="detail-item-content">
                    "${h1}"
                </div>
            </div>
        `).join('');

        content = `
            <div class="details-list">
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-check-circle"></i> Total H1 Tags Found
                    </div>
                    <div class="detail-item-content">
                        ${seoData.h1_tags.length}
                        <br/>
                        <small style="color: var(--text-secondary);">
                            ${seoData.h1_tags.length === 1 
                                ? '✅ Perfect - one H1 tag per page' 
                                : '⚠️ Best practice: use only one H1 tag per page'}
                        </small>
                    </div>
                </div>
                ${h1List}
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-lightbulb"></i> SEO Tip
                    </div>
                    <div class="detail-item-content">
                        Each page should have exactly one H1 tag that describes the main topic. It helps both users and search engines understand what your page is about. Make sure your H1 includes relevant keywords.
                    </div>
                </div>
            </div>
        `;
    } else {
        content = `
            <div class="empty-state">
                <i class="fas fa-times-circle"></i>
                <h3 style="color: var(--danger);">No H1 Tags Found</h3>
                <p>This page is missing H1 tags. Every page should have at least one H1 tag for proper SEO.</p>
                <p style="margin-top: 1.5rem; font-size: 0.9rem;">
                    <strong>Recommendation:</strong> Add an H1 tag to your HTML:
                </p>
                <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; margin-top: 1rem; text-align: left;">
                    <code style="color: var(--primary);">&lt;h1&gt;Your Page Title Here&lt;/h1&gt;</code>
                </div>
            </div>
        `;
    }

    modalBody.innerHTML = content;
    modal.style.display = 'flex';
}

// Close modal when clicking outside of it
document.addEventListener('click', function(event) {
    const modal = document.getElementById('detailModal');
    if (modal && event.target === modal) {
        closeDetailModal();
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeDetailModal();
    }
});

/* ==========================================================================
   Accordion Collapsible Detail Panel Functions
   ========================================================================== */

function toggleCardDetails(panelId, btn) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    
    panel.classList.toggle('open');
    btn.classList.toggle('active');
    
    if (panel.classList.contains('open')) {
        panel.style.maxHeight = panel.scrollHeight + "px";
        btn.querySelector('span').textContent = "Hide Details";
    } else {
        panel.style.maxHeight = "0px";
        btn.querySelector('span').textContent = "View Full Details";
    }
}

function populateSslDetails(sslData) {
    if (!sslData) return;
    document.getElementById('sslProtocolVersion').textContent = sslData.protocol_version || '-';
    document.getElementById('sslCipher').textContent = sslData.cipher_suite || '-';
    document.getElementById('sslIssuer').textContent = sslData.issuer || '-';
    document.getElementById('sslSubjectCN').textContent = sslData.subject_common_name || '-';
    document.getElementById('sslSanDomains').textContent = (sslData.san_domains || []).join(', ') || '-';
    document.getElementById('sslSelfSigned').textContent = sslData.is_self_signed ? 'Yes (Warning)' : 'No (Secure)';
    document.getElementById('sslSerial').textContent = sslData.serial_number || '-';
}

function populateSeoDetails(seoData) {
    if (!seoData) return;
    document.getElementById('seoCanonical').textContent = seoData.canonical_url || 'None';
    document.getElementById('seoRobots').textContent = seoData.robots_meta || 'None';
    document.getElementById('seoViewport').innerHTML = seoData.has_viewport 
        ? '<span style="color: var(--success);"><i class="fas fa-check-circle"></i> Enabled</span>' 
        : '<span style="color: var(--danger);"><i class="fas fa-times-circle"></i> Missing</span>';
    document.getElementById('seoOgTitle').textContent = seoData.og_title || 'None';
    document.getElementById('seoOgDescription').textContent = seoData.og_description || 'None';
    document.getElementById('seoWordCount').textContent = seoData.word_count || '0';
    document.getElementById('seoInternalLinks').textContent = seoData.internal_links || '0';
    document.getElementById('seoExternalLinks').textContent = seoData.external_links || '0';
}

function populatePerformanceDetails(perfData) {
    if (!perfData || perfData.success === false) {
        document.getElementById('perfTbt').textContent = '--';
        document.getElementById('perfCls').textContent = '--';
        const oppsContainer = document.getElementById('perfOpportunities');
        if (oppsContainer) {
            oppsContainer.innerHTML = '<div style="opacity: 0.6; padding: 4px 0;">Performance scan details unavailable.</div>';
        }
        return;
    }
    document.getElementById('perfTbt').textContent = perfData.total_blocking_time || '0 ms';
    document.getElementById('perfCls').textContent = perfData.cumulative_layout_shift || '0';
    
    const oppsContainer = document.getElementById('perfOpportunities');
    if (!oppsContainer) return;
    oppsContainer.innerHTML = '';
    
    const opps = perfData.opportunities || [];
    if (opps.length > 0) {
        opps.forEach(o => {
            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.justifyContent = 'space-between';
            row.style.padding = '4px 0';
            row.style.borderBottom = '1px solid rgba(255,255,255,0.03)';
            row.innerHTML = `
                <span style="opacity: 0.8;"><i class="fas fa-exclamation-circle" style="color: var(--warning); margin-right: 4px;"></i> ${o.title}</span>
                <span style="color: var(--warning); font-weight: 500;">${o.potential_savings}</span>
            `;
            oppsContainer.appendChild(row);
        });
    } else {
        oppsContainer.innerHTML = '<div style="opacity: 0.6; padding: 4px 0;">No significant opportunities identified (score is high).</div>';
    }
}

function populateDnsDetails(dnsData) {
    if (!dnsData) return;
    document.getElementById('dnsSpfPresent').innerHTML = dnsData.has_spf 
        ? '<span style="color: var(--success);"><i class="fas fa-check-circle"></i> Present</span>' 
        : '<span style="color: var(--danger);"><i class="fas fa-times-circle"></i> Missing</span>';
    document.getElementById('dnsSpfRecord').textContent = dnsData.spf_record || 'None';
    
    document.getElementById('dnsDmarcPresent').innerHTML = dnsData.has_dmarc 
        ? '<span style="color: var(--success);"><i class="fas fa-check-circle"></i> Present</span>' 
        : '<span style="color: var(--danger);"><i class="fas fa-times-circle"></i> Missing</span>';
    document.getElementById('dnsDmarcRecord').textContent = dnsData.dmarc_record || 'None';
}

function populateTechnologyDetails(techData) {
    if (!techData) return;
    const additional = techData.additional_detection || {};
    document.getElementById('techServer').textContent = additional.server || 'Unknown';
    document.getElementById('techPoweredBy').textContent = additional.powered_by || 'Unknown';
    document.getElementById('techGenerator').textContent = additional.generator || 'None';
    document.getElementById('techCookies').textContent = (additional.cookies_detected || []).join(', ') || 'None';
}

function populatePortsDetails(portsData) {
    if (!portsData) return;
    const riskDetails = document.getElementById('portsRiskDetails');
    if (!riskDetails) return;
    riskDetails.innerHTML = '';
    
    const openPorts = portsData.open_ports || [];
    const riskNotes = portsData.risk_notes || {};
    let hasWarnings = false;
    
    openPorts.forEach(p => {
        const portNum = p.port;
        const note = riskNotes[portNum] || riskNotes[String(portNum)];
        if (note) {
            hasWarnings = true;
            const item = document.createElement('div');
            item.style.padding = '6px 0';
            item.style.borderBottom = '1px solid rgba(255,255,255,0.03)';
            item.innerHTML = `
                <strong style="color: var(--danger);">Port ${portNum} (${p.service}):</strong> ${note}
            `;
            riskDetails.appendChild(item);
        }
    });
    
    if (!hasWarnings) {
        riskDetails.innerHTML = '<div style="opacity: 0.6; padding: 4px 0; color: var(--success);"><i class="fas fa-check-circle"></i> No common high-risk open ports detected.</div>';
    }
}

function populateHeadersDetails(headersData) {
    if (!headersData) return;
    
    const missingHeaders = headersData.missing_headers || [];
    const descriptions = headersData.header_descriptions || {};
    
    document.getElementById('headersMissingCount').textContent = missingHeaders.length;
    
    const detailsContainer = document.getElementById('headersMissingDetails');
    if (!detailsContainer) return;
    detailsContainer.innerHTML = '';
    
    if (missingHeaders.length > 0) {
        missingHeaders.forEach(header => {
            const desc = descriptions[header] || 'Missing required security header.';
            const item = document.createElement('div');
            item.style.padding = '6px 0';
            item.style.borderBottom = '1px solid rgba(255,255,255,0.03)';
            item.innerHTML = `
                <strong style="color: var(--warning);">${header}:</strong> ${desc}
            `;
            detailsContainer.appendChild(item);
        });
    } else {
        detailsContainer.innerHTML = '<div style="opacity: 0.6; padding: 4px 0; color: var(--success);"><i class="fas fa-check-circle"></i> All key security headers are correctly implemented!</div>';
    }
}

// ==========================================
// AI SECURITY CHATBOX INTERACTION SCRIPT
// ==========================================

function getActiveScanData() {
    // Check if the global 'data' variable exists (index.html context)
    if (typeof data !== 'undefined' && data) {
        return data;
    }
    
    // Check if the global 'currentReport' variable exists (dashboard.html simulated scan context)
    if (typeof currentReport !== 'undefined' && currentReport) {
        return {
            website: document.getElementById('resultWebsite')?.textContent?.replace('Scan Results for ', '') || 'Scanned Website',
            summary: {
                security_score: currentReport.score,
                risk_level: currentReport.status,
                recommendations: []
            },
            scans: {
                ssl: {
                    ssl_enabled: currentReport.ssl?.status?.toLowerCase() === 'valid',
                    protocol_version: currentReport.ssl?.protocol
                },
                headers: {
                    missing_headers: currentReport.vulnerabilities?.high > 0 ? ['Content-Security-Policy', 'Strict-Transport-Security'] : []
                },
                ports: {
                    open_ports: currentReport.vulnerabilities?.critical > 0 ? [{port: 3306, service: 'mysql'}] : []
                },
                performance: {
                    performance_score: currentReport.score >= 80 ? 90 : 50
                }
            }
        };
    }
    return null;
}

function copyCodeText(id) {
    const codeElem = document.getElementById(id);
    if (!codeElem) return;
    
    const text = codeElem.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = codeElem.closest('.code-block-container').querySelector('.code-block-copy-btn');
        if (btn) {
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.classList.remove('copied');
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

function compileTable(rows) {
    if (rows.length === 0) return '';
    let html = '<div class="table-container"><table>';
    
    // Header
    html += '<thead><tr>';
    rows[0].forEach(cell => {
        html += `<th>${cell}</th>`;
    });
    html += '</tr></thead><tbody>';
    
    // Body
    for (let i = 1; i < rows.length; i++) {
        html += '<tr>';
        rows[i].forEach(cell => {
            html += `<td>${cell}</td>`;
        });
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
}

function formatMarkdown(text) {
    if (!text) return "";
    
    // Extract code blocks first to protect code content from formatting
    const codeBlocks = [];
    let escaped = text.replace(/```(\w*)\n([\s\S]+?)```/g, function(match, lang, code) {
        const id = 'code-' + Math.random().toString(36).substr(2, 9);
        const index = codeBlocks.length;
        const cleanCode = code.trim().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const languageLabel = lang ? lang.toUpperCase() : 'CODE';
        codeBlocks.push(`
            <div class="code-block-container">
                <div class="code-block-header">
                    <span class="code-block-lang">${languageLabel}</span>
                    <button class="code-block-copy-btn" onclick="copyCodeText('${id}')">
                        <i class="far fa-copy"></i> Copy
                    </button>
                </div>
                <pre><code class="language-${lang || 'none'}" id="${id}">${cleanCode}</code></pre>
            </div>
        `);
        return `__CODE_BLOCK_${index}__`;
    });
    
    escaped = escaped.replace(/```([\s\S]+?)```/g, function(match, code) {
        const id = 'code-' + Math.random().toString(36).substr(2, 9);
        const index = codeBlocks.length;
        const cleanCode = code.trim().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        codeBlocks.push(`
            <div class="code-block-container">
                <div class="code-block-header">
                    <span class="code-block-lang">CODE</span>
                    <button class="code-block-copy-btn" onclick="copyCodeText('${id}')">
                        <i class="far fa-copy"></i> Copy
                    </button>
                </div>
                <pre><code class="language-none" id="${id}">${cleanCode}</code></pre>
            </div>
        `);
        return `__CODE_BLOCK_${index}__`;
    });

    // Escape raw HTML outside code blocks
    escaped = escaped
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

    // Inline code
    escaped = escaped.replace(/`([^`\n]+?)`/g, '<code>$1</code>');
    
    // Bold
    escaped = escaped.replace(/\*\*([^*]+?)\*\*/g, '<strong>$1</strong>');
    
    // Headings
    escaped = escaped.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    escaped = escaped.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
    escaped = escaped.replace(/^## (.*$)/gim, '<h2>$1</h2>');

    // Split lines for list and table processing
    let lines = escaped.split('\n');
    let inList = false;
    let inOrderList = false;
    let inTable = false;
    let tableRows = [];
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        // Handle Tables
        if (line.startsWith('|') && line.endsWith('|')) {
            if (inList) { lines[i-1] += '</ul>'; inList = false; }
            if (inOrderList) { lines[i-1] += '</ol>'; inOrderList = false; }
            
            if (line.includes('---') || line.includes('-:-')) {
                lines[i] = '';
                continue;
            }
            
            let cells = line.split('|').map(c => c.trim()).filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
            tableRows.push(cells);
            lines[i] = '';
            inTable = true;
            continue;
        } else if (inTable) {
            lines[i-1] = compileTable(tableRows);
            tableRows = [];
            inTable = false;
        }
        
        // Handle Lists
        if (line.startsWith('- ') || line.startsWith('* ')) {
            let content = line.substring(2);
            if (!inList) {
                lines[i] = '<ul><li>' + content + '</li>';
                inList = true;
            } else {
                lines[i] = '<li>' + content + '</li>';
            }
        } else if (/^\d+\.\s/.test(line)) {
            let content = line.replace(/^\d+\.\s/, '');
            if (!inOrderList) {
                lines[i] = '<ol><li>' + content + '</li>';
                inOrderList = true;
            } else {
                lines[i] = '<li>' + content + '</li>';
            }
        } else {
            if (inList) {
                lines[i-1] = lines[i-1] + '</ul>';
                inList = false;
            }
            if (inOrderList) {
                lines[i-1] = lines[i-1] + '</ol>';
                inOrderList = false;
            }
        }
    }
    
    if (inTable) {
        lines[lines.length - 1] = compileTable(tableRows);
    }
    if (inList) lines[lines.length - 1] = lines[lines.length - 1] + '</ul>';
    if (inOrderList) lines[lines.length - 1] = lines[lines.length - 1] + '</ol>';
    
    escaped = lines.filter(l => l !== '').join('\n');
    
    // Paragraph breaks
    escaped = escaped.replace(/\n\n/g, '</p><p>');
    escaped = escaped.replace(/\n/g, '<br>');
    
    escaped = '<p>' + escaped + '</p>';
    escaped = escaped.replace(/<p><(ul|ol|h2|h3|h4|div|table)/g, '<$1');
    escaped = escaped.replace(/<\/(ul|ol|h2|h3|h4|div|table)><\/p>/g, '</$1>');
    escaped = escaped.replace(/<br><(ul|ol|li|h2|h3|h4|div|table)/g, '<$1');
    escaped = escaped.replace(/<\/(ul|ol|li|h2|h3|h4|div|table)><br>/g, '</$1>');
    escaped = escaped.replace(/<p>\s*<\/p>/g, '');
    
    // Re-inject code blocks
    for (let index = 0; index < codeBlocks.length; index++) {
        escaped = escaped.replace(`__CODE_BLOCK_${index}__`, codeBlocks[index]);
    }
    
    return escaped;
}

async function sendChatMessage(isSuggestion = false) {
    const chatInput = document.getElementById('chatInput');
    if (!chatInput) return;
    
    const message = chatInput.value.trim();
    if (!message) return;
    
    chatInput.value = '';
    
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;
    
    // Hide suggestion chips
    const suggestionsDiv = document.getElementById('chatSuggestions');
    if (suggestionsDiv) {
        suggestionsDiv.style.display = 'none';
    }
    
    // 1. Append User Message
    const userMessageDiv = document.createElement('div');
    userMessageDiv.className = 'chat-message user-message animate-message';
    userMessageDiv.innerHTML = `
        <div class="message-avatar"><i class="fas fa-user"></i></div>
        <div class="message-text">${message}</div>
    `;
    chatMessages.appendChild(userMessageDiv);
    chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
    
    // 2. Add Typing Indicator
    const typingMessageDiv = document.createElement('div');
    typingMessageDiv.className = 'chat-message bot-message typing-indicator-container animate-message';
    typingMessageDiv.innerHTML = `
        <div class="message-avatar"><i class="fas fa-robot"></i></div>
        <div class="message-text">
            <div class="typing-indicator">
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
            </div>
        </div>
    `;
    chatMessages.appendChild(typingMessageDiv);
    chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
    
    // 3. Make API Call to FastAPI
    try {
        const scanData = getActiveScanData();
        const savedKey = localStorage.getItem('gemini_api_key') || '';
        const host = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || !window.location.hostname
            ? 'http://localhost:8000'
            : 'https://website-security-scanner-2-1.onrender.com';
            
        const selectedModule = autoDetectActiveModule();
 
        const response = await fetch(`${host}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
                scan_results: scanData,
                api_key: savedKey,
                module: selectedModule,
                is_suggestion: isSuggestion
            })
        });
        
        // Remove typing indicator
        const indicator = document.querySelector('.typing-indicator-container');
        if (indicator) indicator.remove();
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        
        const responseData = await response.json();
        
        // Create response source badge
        let badgeHtml = '';
        if (responseData.source === 'rule') {
            badgeHtml = `<span class="response-source-badge rule-badge"><i class="fas fa-wrench"></i> Rule Engine</span>`;
        } else if (responseData.source === 'ai') {
            badgeHtml = `<span class="response-source-badge ai-badge"><i class="fas fa-robot"></i> Hybrid AI${responseData.cached ? ' (Cached)' : ''}</span>`;
        } else if (responseData.source === 'fallback') {
            badgeHtml = `<span class="response-source-badge fallback-badge"><i class="fas fa-life-ring"></i> Offline Helper</span>`;
        }
 
        // 4. Append Bot Response
        const botMessageDiv = document.createElement('div');
        botMessageDiv.className = 'chat-message bot-message animate-message';
        botMessageDiv.innerHTML = `
            <div class="message-avatar"><i class="fas fa-robot"></i></div>
            <div class="message-text">
                ${formatMarkdown(responseData.response)}
                ${badgeHtml}
            </div>
        `;
        chatMessages.appendChild(botMessageDiv);
        chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
        
    } catch (error) {
        console.error('Error fetching chat response:', error);
        
        // Remove typing indicator
        const indicator = document.querySelector('.typing-indicator-container');
        if (indicator) indicator.remove();
        
        const errorMessageDiv = document.createElement('div');
        errorMessageDiv.className = 'chat-message bot-message animate-message';
        errorMessageDiv.innerHTML = `
            <div class="message-avatar"><i class="fas fa-robot"></i></div>
            <div class="message-text" style="color: var(--danger);">
                <i class="fas fa-exclamation-triangle"></i> Sorry, I couldn't reach the backend advisor service. Please make sure the backend server is running and try again.
            </div>
        `;
        chatMessages.appendChild(errorMessageDiv);
        chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
    }
}
 
function askSuggestedQuestion(qText) {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.value = qText;
        sendChatMessage(true);
    }
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter') {
        sendChatMessage();
    }
}

const MODULE_SUGGESTIONS = {
    general: [
        'Explain My Scan',
        'Improve Website Security',
        'Website Security Tips',
        'Beginner Guide',
        'Fix My Website'
    ],
    ssl: [
        'Explain SSL',
        'Check SSL Status',
        'How to get free SSL',
        'Fix SSL expiration',
        'Is self-signed SSL safe?'
    ],
    headers: [
        'Explain Security Headers',
        'How to fix CSP',
        'What is HSTS?',
        'Configure X-Frame-Options',
        'Add missing headers'
    ],
    ports: [
        'What is a port scan?',
        'Fix open ports',
        'Is port 80/443 safe?',
        'Secure database ports',
        'Vulnerable service mitigation'
    ],
    dns: [
        'What is DNS?',
        'Verify MX & A records',
        'Check SPF & DMARC',
        'How to set up DMARC'
    ],
    seo: [
        'Explain SEO scan',
        'Fix missing meta tags',
        'Why H1 count matters',
        'Optimize image alt text'
    ],
    performance: [
        'Improve website speed',
        'What is FCP & LCP?',
        'Optimize Speed Index',
        'Reduce page load time'
    ],
    technology: [
        'What technology was detected?',
        'Are my backend versions safe?',
        'Explain server cookies safety',
        'Hide server signature'
    ]
};

function updateChatSuggestions(module) {
    const suggestionsDiv = document.getElementById('chatSuggestions');
    if (!suggestionsDiv) return;
    
    const suggestions = MODULE_SUGGESTIONS[module] || MODULE_SUGGESTIONS['general'];
    
    suggestionsDiv.innerHTML = suggestions
        .map(q => `<button onclick="askSuggestedQuestion('${q.replace(/'/g, "\\\'")}')">${q}</button>`)
        .join('');
        
    suggestionsDiv.style.display = 'flex';
}

/* Auto-detect the currently visible scan module from the page */
function autoDetectActiveModule() {
    // Priority 1: any expanded detail panel
    const panelMap = {
        sslDetails:     'ssl',
        headersDetails: 'headers',
        portsDetails:   'ports',
        dnsDetails:     'dns',
        seoDetails:     'seo',
        perfDetails:    'performance',
        techDetails:    'technology'
    };
    for (const [id, mod] of Object.entries(panelMap)) {
        const el = document.getElementById(id);
        if (el && el.classList.contains('open')) return mod;
    }

    // Priority 2: which result-card is most centered in viewport
    const cardMap = [
        { selector: '.ssl-card',         module: 'ssl'         },
        { selector: '.headers-card',     module: 'headers'     },
        { selector: '.port-card',        module: 'ports'       },
        { selector: '.dns-card',         module: 'dns'         },
        { selector: '.seo-card',         module: 'seo'         },
        { selector: '.performance-card', module: 'performance' },
        { selector: '.result-card:not(.ssl-card):not(.headers-card):not(.port-card):not(.dns-card):not(.seo-card):not(.performance-card)', module: 'technology' }
    ];
    const vMid = window.innerHeight / 2;
    let bestMod = 'general', bestDist = Infinity;
    for (const { selector, module } of cardMap) {
        document.querySelectorAll(selector).forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.bottom < 0 || rect.top > window.innerHeight) return;
            const mid  = (rect.top + rect.bottom) / 2;
            const dist = Math.abs(mid - vMid);
            if (dist < bestDist) { bestDist = dist; bestMod = module; }
        });
    }
    return bestMod;
}

function handleModuleChange() {
    const module = autoDetectActiveModule();
    updateChatSuggestions(module);
}

function toggleChatbot() {
    const chatbotWidget = document.getElementById('aiChatbotWidget');
    if (!chatbotWidget) return;
    chatbotWidget.classList.toggle('open');
    // When opening, seed suggestions based on visible module
    if (chatbotWidget.classList.contains('open')) {
        handleModuleChange();
    }
}

/* Chatbot Settings Panel Functionality */
function toggleChatSettings() {
    const panel = document.getElementById('chatbotSettingsPanel');
    if (panel) {
        if (panel.style.display === 'none') {
            panel.style.display = 'block';
            const input = document.getElementById('geminiApiKeyInput');
            if (input) {
                input.value = localStorage.getItem('gemini_api_key') || '';
            }
        } else {
            panel.style.display = 'none';
        }
    }
}

function saveGeminiApiKey() {
    const input = document.getElementById('geminiApiKeyInput');
    const status = document.getElementById('settingsKeyStatus');
    if (!input || !status) return;

    const key = input.value.trim();
    if (!key) {
        status.textContent = '⚠️ Please enter a valid API Key.';
        status.style.color = 'var(--danger)';
        return;
    }

    localStorage.setItem('gemini_api_key', key);
    status.textContent = '✅ API Key saved successfully!';
    status.style.color = 'var(--success)';
    
    updateChatbotStatus();
    
    setTimeout(() => {
        toggleChatSettings();
        status.textContent = '';
    }, 1500);
}

function clearGeminiApiKey() {
    const input = document.getElementById('geminiApiKeyInput');
    const status = document.getElementById('settingsKeyStatus');
    if (input) input.value = '';
    
    localStorage.removeItem('gemini_api_key');
    if (status) {
        status.textContent = '🗑️ API Key cleared.';
        status.style.color = 'var(--warning)';
    }
    
    updateChatbotStatus();
    
    setTimeout(() => {
        toggleChatSettings();
        if (status) status.textContent = '';
    }, 1500);
}

function updateChatbotStatus() {
    const statusText = document.getElementById('chatbotStatus');
    if (!statusText) return;
    
    const key = localStorage.getItem('gemini_api_key');
    if (key) {
        statusText.innerHTML = '<span class="status-dot online" style="background-color: var(--success);"></span> Hybrid Mode';
        statusText.style.color = 'var(--success)';
    } else {
        statusText.innerHTML = '<span class="status-dot" style="background-color: #9ca3af;"></span> Rule Mode';
        statusText.style.color = 'var(--text-secondary)';
    }
}

// Wire scroll listener so pills update as the user scrolls through cards
window.addEventListener('scroll', () => {
    const widget = document.getElementById('aiChatbotWidget');
    if (widget && widget.classList.contains('open')) handleModuleChange();
}, { passive: true });

// Wire expand-btn clicks so pills update immediately when a card is opened
document.addEventListener('click', e => {
    if (e.target.closest('.expand-btn') || e.target.closest('.card-expand-toggle')) {
        setTimeout(handleModuleChange, 50);
    }
});

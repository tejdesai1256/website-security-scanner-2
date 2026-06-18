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

        // Show loading
        const scanBtn =
            document.querySelector('.scan-btn');

        const originalText =
            scanBtn.innerHTML;

        scanBtn.innerHTML =
            '<i class="fas fa-spinner fa-spin"></i> Scanning...';

        scanBtn.disabled = true;

        // Backend API
        const apiUrl = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://localhost:8000/scan'
            : `${window.location.origin}/api/scan`;
        
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
        // SCORE
        // =========================

        const score =
            data.summary.security_score;

        document.getElementById(
            'scoreValue'
        ).textContent =
            score;

        document.getElementById(
            'scoreStatus'
        ).textContent =
            data.summary.risk_level;

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
            'HTTPS';

        document.getElementById(
            'sslExpires'
        ).textContent =
            data.scans.ssl.expiry_date || '-';

        document.getElementById(
            'sslCert'
        ).textContent =
            data.scans.ssl.success
                ? 'Valid'
                : 'Invalid';

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

        document.getElementById(
            'performanceScore'
        ).textContent =
            data.scans.performance.performance_score;

        document.getElementById(
            'fcp'
        ).textContent =
            data.scans.performance.first_contentful_paint;

        document.getElementById(
            'lcp'
        ).textContent =
            data.scans.performance.largest_contentful_paint;

        document.getElementById(
            'speedIndex'
        ).textContent =
            data.scans.performance.speed_index;


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

    const reportContent = `
WEBSITE SECURITY SCAN REPORT
========================================

Website: ${website || '-'}
URL: ${url || '-'}
Scan Date: ${date || new Date().toLocaleString()}

SECURITY SCORE: ${score}/100 (${status} Risk)

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
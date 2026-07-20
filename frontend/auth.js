// Authentication System
class AuthSystem {
    constructor() {
        this.users = this.loadUsers();
        this.currentUser = this.loadCurrentUser();
        this.googleClientId = localStorage.getItem('google_client_id') || '';
    }

    // Load users from localStorage
    loadUsers() {
        const stored = localStorage.getItem('users');

        if (stored) {
            return JSON.parse(stored);
        }

        // Default demo user
        const defaultUsers = {
            'demo@example.com': {
                email: 'demo@example.com',
                password: this.hashPassword('Demo@123'),
                name: 'Demo User',
                createdAt: new Date().toISOString(),
                scansRemaining: 100
            }
        };

        localStorage.setItem('users', JSON.stringify(defaultUsers));

        return defaultUsers;
    }

    // Save users
    saveUsers() {
        localStorage.setItem('users', JSON.stringify(this.users));
    }

    // Load current user
    loadCurrentUser() {
        const stored = localStorage.getItem('currentUser');
        return stored ? JSON.parse(stored) : null;
    }

    // Save current user
    saveCurrentUser(user) {
        this.currentUser = user;
        localStorage.setItem('currentUser', JSON.stringify(user));
    }

    // Clear session
    clearSession() {
        this.currentUser = null;
        localStorage.removeItem('currentUser');
    }

    // Better password encoding
    hashPassword(password) {
        return btoa(unescape(encodeURIComponent(password)));
    }

    // Validate email
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // Validate password
    validatePassword(password) {
        return {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[!@#$%^&*]/.test(password)
        };
    }

    // Register user
    register(email, password, confirmPassword, name) {
        const errors = [];

        // Clean inputs
        email = email.trim().toLowerCase();
        password = password.trim();
        confirmPassword = confirmPassword.trim();
        name = name.trim();

        // Validation
        if (!email || !password || !confirmPassword || !name) {
            errors.push('All fields are required');
        }

        if (!this.validateEmail(email)) {
            errors.push('Invalid email format');
        }

        if (this.users[email]) {
            errors.push('Email already registered');
        }

        if (password !== confirmPassword) {
            errors.push('Passwords do not match');
        }

        const passwordValidation = this.validatePassword(password);

        if (!passwordValidation.length) {
            errors.push('Password must be at least 8 characters long');
        }

        if (!passwordValidation.uppercase) {
            errors.push('Password must contain an uppercase letter');
        }

        if (!passwordValidation.lowercase) {
            errors.push('Password must contain a lowercase letter');
        }

        if (!passwordValidation.number) {
            errors.push('Password must contain a number');
        }

        if (!passwordValidation.special) {
            errors.push('Password must contain a special character (!@#$%^&*)');
        }

        // Return errors
        if (errors.length > 0) {
            return {
                success: false,
                errors
            };
        }

        // Save user
        this.users[email] = {
            email,
            password: this.hashPassword(password),
            name,
            createdAt: new Date().toISOString(),
            scansRemaining: 100
        };

        this.saveUsers();

        return {
            success: true,
            message: 'Registration successful! Please log in.'
        };
    }

    // Login user
    login(email, password) {
        const errors = [];

        // Clean inputs
        email = email.trim().toLowerCase();
        password = password.trim();

        // Validation
        if (!email || !password) {
            errors.push('Email and password are required');
        }

        if (!this.validateEmail(email)) {
            errors.push('Invalid email format');
        }

        // Find user
        const user = this.users[email];

        if (!user) {
            errors.push('Invalid email or password');

            return {
                success: false,
                errors
            };
        }

        // Check password
        if (user.password !== this.hashPassword(password)) {
            errors.push('Invalid email or password');

            return {
                success: false,
                errors
            };
        }

        // Create session
        const sessionUser = {
            email: user.email,
            name: user.name,
            createdAt: user.createdAt,
            scansRemaining: user.scansRemaining || 100,
            loginTime: new Date().toISOString()
        };

        this.saveCurrentUser(sessionUser);

        return {
            success: true,
            user: sessionUser
        };
    }

    // Logout
    logout() {
        this.clearSession();
    }

    // Check auth
    isAuthenticated() {
        return this.currentUser !== null;
    }

    // Get current user
    getCurrentUser() {
        return this.currentUser;
    }

    // Reduce scans
    decrementScans(email) {
        email = email.trim().toLowerCase();

        if (this.users[email]) {
            this.users[email].scansRemaining =
                (this.users[email].scansRemaining || 100) - 1;

            this.saveUsers();

            if (this.currentUser && this.currentUser.email === email) {
                this.currentUser.scansRemaining =
                    this.users[email].scansRemaining;

                this.saveCurrentUser(this.currentUser);
            }
        }
    }

    // Decode Google JWT token client-side
    decodeJwt(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(
                atob(base64)
                    .split('')
                    .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                    .join('')
            );
            return JSON.parse(jsonPayload);
        } catch (e) {
            console.error('Error decoding Google JWT', e);
            return null;
        }
    }

    // Handle standard or mock Google sign-in response
    handleGoogleSignIn(credentialOrMockData) {
        let email, name, picture;

        if (typeof credentialOrMockData === 'string') {
            // Real JWT credential
            const payload = this.decodeJwt(credentialOrMockData);
            if (!payload) {
                return { success: false, errors: ['Failed to parse Google account information'] };
            }
            email = payload.email;
            name = payload.name;
            picture = payload.picture;
        } else {
            // Mock account data
            email = credentialOrMockData.email;
            name = credentialOrMockData.name;
            picture = credentialOrMockData.picture;
        }

        email = email.trim().toLowerCase();
        name = name.trim();

        // Register user if not exists
        if (!this.users[email]) {
            this.users[email] = {
                email,
                password: null, // Google user has no local password
                name,
                picture: picture || '',
                createdAt: new Date().toISOString(),
                scansRemaining: 100,
                isGoogleUser: true
            };
            this.saveUsers();
        } else {
            // Update picture or profile if exists
            this.users[email].name = name;
            if (picture) {
                this.users[email].picture = picture;
            }
            this.users[email].isGoogleUser = true;
            this.saveUsers();
        }

        // Create session
        const sessionUser = {
            email: this.users[email].email,
            name: this.users[email].name,
            picture: this.users[email].picture,
            createdAt: this.users[email].createdAt,
            scansRemaining: this.users[email].scansRemaining || 100,
            loginTime: new Date().toISOString(),
            isGoogleUser: true
        };

        this.saveCurrentUser(sessionUser);

        // Redirect to dashboard
        setTimeout(() => {
            redirectToDashboard();
        }, 1200);

        return { success: true, user: sessionUser };
    }

    // Initialize/Trigger Google Flow
    initiateGoogleFlow() {
        const savedClientId = localStorage.getItem('google_client_id') || '';

        if (savedClientId && savedClientId.trim() !== '' && savedClientId !== 'YOUR_GOOGLE_CLIENT_ID') {
            // Real GSI authentication setup
            if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
                try {
                    google.accounts.id.initialize({
                        client_id: savedClientId,
                        callback: window.handleGoogleCredentialResponse,
                        context: 'signin',
                        ux_mode: 'popup',
                        auto_prompt: false
                    });
                    google.accounts.id.prompt();
                    return;
                } catch (err) {
                    console.error('Error starting Google Identity Services:', err);
                }
            } else {
                console.warn('Google Identity Services SDK not loaded yet. Using mock fallback.');
            }
        }

        // Mock fallback
        this.showMockGoogleChooser();
    }

    showMockGoogleChooser() {
        // Create modal container if not exists
        let modal = document.getElementById('googleMockModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'googleMockModal';
            modal.className = 'google-mock-modal';
            modal.innerHTML = `
                <div class="google-mock-card" id="googleMockCard">
                    <button class="google-mock-close" onclick="auth.hideMockGoogleChooser()">&times;</button>
                    
                    <div id="googleMockAccountsView">
                        <div class="google-mock-header">
                            <div class="google-mock-logo">
                                <span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span>
                            </div>
                            <h2>Choose an account</h2>
                            <p>to continue to JobJockey Security</p>
                        </div>
                        
                        <div class="google-mock-accounts">
                            <div class="google-mock-account-item" onclick="auth.selectMockAccount('Tej Desai', 'tejdesai111@gmail.com', 'AD')">
                                <div class="google-mock-avatar" style="background: #4285F4;">TD</div>
                                <div class="google-mock-info">
                                    <span class="google-mock-name">Tej Desai</span>
                                    <span class="google-mock-email">tejdesai111@gmail.com</span>
                                </div>
                            </div>
                            <div class="google-mock-account-item" onclick="auth.selectMockAccount('Dinesh Pawar', 'dinesh@gmail.com', 'BS')">
                                <div class="google-mock-avatar" style="background: #34A853;">DP</div>
                                <div class="google-mock-info">
                                    <span class="google-mock-name">Dinesh Pawar</span>
                                    <span class="google-mock-email">dinesh@gmail.com</span>
                                </div>
                            </div>
                            <div class="google-mock-account-item" onclick="auth.selectMockAccount('Vikrant Bhagat', 'vikrantbhagat89@gmail.com', 'VB')">
                                <div class="google-mock-avatar" style="background: #FBBC05;">VB</div>
                                <div class="google-mock-info">
                                    <span class="google-mock-name">Vikrant Bhagat</span>
                                    <span class="google-mock-email">vikrantbhagat89@gmail.com</span>        
                                </div>
                            </div>
                        </div>
                        
                        <div class="google-mock-divider"></div>
                        
                        <button class="google-mock-btn-secondary" onclick="auth.showCustomMockForm()">
                            <i class="fas fa-user-plus"></i> Use another account
                        </button>
                        
                        <div class="google-mock-custom-form" id="googleMockCustomForm">
                            <input type="text" id="googleMockCustomName" placeholder="Full Name" required>
                            <input type="email" id="googleMockCustomEmail" placeholder="Email Address" required>
                            <button class="google-mock-custom-submit" onclick="auth.submitCustomMockAccount()">Sign In</button>
                        </div>
                    </div>
                    
                    <div class="google-mock-loader-container" id="googleMockLoader">
                        <div class="google-mock-spinner"></div>
                        <h3 style="color: var(--primary); font-weight: 500; margin: 0;">Verifying account...</h3>
                        <p style="color: var(--text-secondary); font-size: 0.85rem; margin: 0;">Connecting to Google secure servers</p>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        // Reset view states
        document.getElementById('googleMockAccountsView').style.display = 'block';
        document.getElementById('googleMockLoader').style.display = 'none';
        document.getElementById('googleMockCustomForm').style.display = 'none';

        // Show modal
        setTimeout(() => {
            modal.classList.add('show');
        }, 10);
    }

    hideMockGoogleChooser() {
        const modal = document.getElementById('googleMockModal');
        if (modal) {
            modal.classList.remove('show');
        }
    }

    showCustomMockForm() {
        const form = document.getElementById('googleMockCustomForm');
        form.style.display = form.style.display === 'flex' ? 'none' : 'flex';
    }

    selectMockAccount(name, email, initials) {
        // Show loading spinner
        document.getElementById('googleMockAccountsView').style.display = 'none';
        document.getElementById('googleMockLoader').style.display = 'flex';

        // Generate an SVG or color-based dummy avatar for the user
        const colorMap = { 'AD': '#4285F4', 'BS': '#34A853', 'CT': '#FBBC05' };
        const avatarBg = colorMap[initials] || '#7c3aed';

        // We can create a simple data URI for a colored avatar circle with initials
        const canvas = document.createElement('canvas');
        canvas.width = 100;
        canvas.height = 100;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = avatarBg;
        ctx.beginPath();
        ctx.arc(50, 50, 50, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 45px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(initials, 50, 50);
        const pictureUrl = canvas.toDataURL();

        setTimeout(() => {
            this.handleGoogleSignIn({
                email,
                name,
                picture: pictureUrl
            });
            this.hideMockGoogleChooser();
        }, 1200);
    }

    submitCustomMockAccount() {
        const nameInput = document.getElementById('googleMockCustomName');
        const emailInput = document.getElementById('googleMockCustomEmail');
        const name = nameInput.value.trim();
        const email = emailInput.value.trim();

        if (!name || !email) {
            alert('Please enter both name and email');
            return;
        }

        if (!this.validateEmail(email)) {
            alert('Please enter a valid email address');
            return;
        }

        const initials = name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() || 'U';

        // Canvas profile picture
        const canvas = document.createElement('canvas');
        canvas.width = 100;
        canvas.height = 100;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#7c3aed';
        ctx.beginPath();
        ctx.arc(50, 50, 50, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 45px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(initials, 50, 50);
        const pictureUrl = canvas.toDataURL();

        document.getElementById('googleMockAccountsView').style.display = 'none';
        document.getElementById('googleMockLoader').style.display = 'flex';

        setTimeout(() => {
            this.handleGoogleSignIn({
                email,
                name,
                picture: pictureUrl
            });
            this.hideMockGoogleChooser();
        }, 1200);
    }
}

// Global hook for Google GSI callback
window.handleGoogleCredentialResponse = function (response) {
    if (auth) {
        auth.handleGoogleSignIn(response.credential);
    }
};

// Initialize auth system
const auth = new AuthSystem();

// Redirect functions
function redirectToLogin() {
    window.location.href = 'login.html';
}

function redirectToDashboard() {
    window.location.href = 'dashboard.html';
}

function redirectToHome() {
    window.location.href = 'index.html';
}

// Check auth
function checkAuth(redirectIfNotAuth = true) {
    if (!auth.isAuthenticated()) {
        if (redirectIfNotAuth) {
            redirectToLogin();
        }

        return false;
    }

    return true;
}

// Protect page
function protectPage() {
    if (!checkAuth(true)) {
        return false;
    }

    return true;
}
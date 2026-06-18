// Authentication System
class AuthSystem {
    constructor() {
        this.users = this.loadUsers();
        this.currentUser = this.loadCurrentUser();
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
}

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
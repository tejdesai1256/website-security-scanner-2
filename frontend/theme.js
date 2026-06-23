(function () {
    const STORAGE_KEY = "jobjockey-theme";
    const LEGACY_STORAGE_KEY = "theme";
    const THEMES = ["dark", "light"];
    const prefersLight = window.matchMedia("(prefers-color-scheme: light)");

    function getStoredTheme() {
        const storedTheme =
            localStorage.getItem(STORAGE_KEY) ||
            localStorage.getItem(LEGACY_STORAGE_KEY);

        return THEMES.includes(storedTheme) ? storedTheme : null;
    }

    function getPreferredTheme() {
        return getStoredTheme() || (prefersLight.matches ? "light" : "dark");
    }

    function updateToggleButton(button, theme) {
        const isLight = theme === "light";

        button.setAttribute("aria-label", `Switch to ${isLight ? "dark" : "light"} mode`);
        button.setAttribute("aria-pressed", String(isLight));
        button.setAttribute("title", `Switch to ${isLight ? "dark" : "light"} mode`);
        button.innerHTML = `<i class="fas ${isLight ? "fa-sun" : "fa-moon"}" aria-hidden="true"></i>`;
    }

    function applyTheme(theme, persist) {
        const nextTheme = THEMES.includes(theme) ? theme : "dark";

        document.documentElement.dataset.theme = nextTheme;
        document.documentElement.style.colorScheme = nextTheme;

        if (document.body) {
            document.body.classList.toggle("light-mode", nextTheme === "light");
        }

        document.querySelectorAll("[data-theme-toggle]").forEach(button => {
            updateToggleButton(button, nextTheme);
        });

        if (persist) {
            localStorage.setItem(STORAGE_KEY, nextTheme);
            localStorage.setItem(LEGACY_STORAGE_KEY, nextTheme);
        }

        return nextTheme;
    }

    function toggleTheme() {
        const currentTheme = document.documentElement.dataset.theme || getPreferredTheme();
        return applyTheme(currentTheme === "light" ? "dark" : "light", true);
    }

    function initThemeControls() {
        applyTheme(getPreferredTheme(), false);

        document.querySelectorAll("[data-theme-toggle]").forEach(button => {
            button.addEventListener("click", toggleTheme);
        });
    }

    applyTheme(getPreferredTheme(), false);

    document.addEventListener("DOMContentLoaded", initThemeControls);

    prefersLight.addEventListener("change", () => {
        if (!getStoredTheme()) {
            applyTheme(getPreferredTheme(), false);
        }
    });

    window.JobJockeyTheme = {
        apply: applyTheme,
        toggle: toggleTheme,
        get: () => document.documentElement.dataset.theme || getPreferredTheme()
    };
})();

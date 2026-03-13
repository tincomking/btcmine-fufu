/* === FUFU Intelligence — Preferences (Theme / Language / Font Size) === */

const PREFS_KEY = "fufu_prefs";

const DEFAULT_PREFS = { theme: "dark", lang: "zh", fontSize: 14 };

function loadPrefs() {
    try {
        const saved = JSON.parse(localStorage.getItem(PREFS_KEY));
        return { ...DEFAULT_PREFS, ...saved };
    } catch { return { ...DEFAULT_PREFS }; }
}

function savePrefs(prefs) {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
}

function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
}

function applyFontSize(size) {
    document.documentElement.style.setProperty("--base-font-size", size + "px");
    document.body.style.fontSize = size + "px";
}

function applyLang(lang) {
    document.documentElement.setAttribute("data-lang", lang);
    // Toggle visibility of lang spans
    document.querySelectorAll(".lang-zh").forEach(el => {
        el.style.display = lang === "zh" ? "" : "none";
    });
    document.querySelectorAll(".lang-en").forEach(el => {
        el.style.display = lang === "en" ? "" : "none";
    });
    // Update elements with data-zh / data-en attributes
    document.querySelectorAll("[data-zh][data-en]").forEach(el => {
        el.textContent = lang === "zh" ? el.getAttribute("data-zh") : el.getAttribute("data-en");
    });
    // Update placeholders
    document.querySelectorAll("[data-ph-zh][data-ph-en]").forEach(el => {
        el.placeholder = lang === "zh" ? el.getAttribute("data-ph-zh") : el.getAttribute("data-ph-en");
    });
}

function applyAllPrefs(prefs) {
    applyTheme(prefs.theme);
    applyFontSize(prefs.fontSize);
    applyLang(prefs.lang);
}

/* Build the settings toolbar and insert it into a target container */
function initPrefsToolbar(containerId) {
    const prefs = loadPrefs();
    applyAllPrefs(prefs);

    const container = document.getElementById(containerId);
    if (!container) return;

    const toolbar = document.createElement("div");
    toolbar.className = "prefs-toolbar";
    toolbar.innerHTML = `
        <button id="pref-lang" class="pref-btn" title="中/EN">
            <span class="pref-icon">${prefs.lang === "zh" ? "EN" : "中"}</span>
        </button>
        <button id="pref-theme" class="pref-btn" title="Theme">
            <span class="pref-icon">${prefs.theme === "dark" ? "☀" : "☾"}</span>
        </button>
        <div class="pref-fontsize">
            <button id="pref-font-down" class="pref-btn pref-btn-sm" title="A-">A-</button>
            <span id="pref-font-val" class="pref-font-val">${prefs.fontSize}</span>
            <button id="pref-font-up" class="pref-btn pref-btn-sm" title="A+">A+</button>
        </div>
    `;
    container.appendChild(toolbar);

    // Language toggle
    document.getElementById("pref-lang").addEventListener("click", () => {
        prefs.lang = prefs.lang === "zh" ? "en" : "zh";
        savePrefs(prefs);
        applyLang(prefs.lang);
        document.querySelector("#pref-lang .pref-icon").textContent = prefs.lang === "zh" ? "EN" : "中";
    });

    // Theme toggle
    document.getElementById("pref-theme").addEventListener("click", () => {
        prefs.theme = prefs.theme === "dark" ? "light" : "dark";
        savePrefs(prefs);
        applyTheme(prefs.theme);
        document.querySelector("#pref-theme .pref-icon").textContent = prefs.theme === "dark" ? "☀" : "☾";
    });

    // Font size
    document.getElementById("pref-font-down").addEventListener("click", () => {
        prefs.fontSize = Math.max(11, prefs.fontSize - 1);
        savePrefs(prefs);
        applyFontSize(prefs.fontSize);
        document.getElementById("pref-font-val").textContent = prefs.fontSize;
    });
    document.getElementById("pref-font-up").addEventListener("click", () => {
        prefs.fontSize = Math.min(20, prefs.fontSize + 1);
        savePrefs(prefs);
        applyFontSize(prefs.fontSize);
        document.getElementById("pref-font-val").textContent = prefs.fontSize;
    });
}

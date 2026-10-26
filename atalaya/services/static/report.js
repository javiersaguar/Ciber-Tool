"use strict";
(() => {
  const find = (id) => document.getElementById(id);
  const cards = [...document.querySelectorAll(".finding")];
  const modules = [...document.querySelectorAll(".module")];
  const theme = find("theme");
  let selectedTheme = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  try { selectedTheme = localStorage.getItem("atalaya-theme") || selectedTheme; } catch {}
  function setTheme(value) {
    document.documentElement.dataset.theme = value;
    theme.textContent = value === "dark" ? "Modo claro" : "Modo oscuro";
    theme.setAttribute("aria-label", "Activar " + theme.textContent.toLowerCase());
  }
  setTheme(selectedTheme);
  theme.addEventListener("click", () => {
    selectedTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(selectedTheme);
    try { localStorage.setItem("atalaya-theme", selectedTheme); } catch {}
  });
  find("print").addEventListener("click", () => window.print());
  document.querySelector(".filters").addEventListener("submit", (event) => event.preventDefault());
  function filter() {
    const query = find("search").value.trim().toLocaleLowerCase();
    const severity = find("severity").value;
    const module = find("module").value;
    let visible = 0;
    cards.forEach((card) => {
      card.hidden = !!((severity && card.dataset.severity !== severity) ||
        (module && card.dataset.module !== module) ||
        (query && !card.textContent.toLocaleLowerCase().includes(query)));
      if (!card.hidden) visible++;
    });
    const active = !!(query || severity || module);
    modules.forEach((section) => {
      section.hidden = active && ![...section.querySelectorAll(".finding")].some((card) => !card.hidden);
    });
    find("visible-count").textContent = visible + (visible === 1 ? " resultado" : " resultados");
    find("filter-empty").hidden = !active || visible > 0;
  }
  ["search", "severity", "module"].forEach((id) => find(id).addEventListener("input", filter));
  filter();
})();

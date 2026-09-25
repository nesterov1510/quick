document.addEventListener("DOMContentLoaded", () => {
    const toggle = document.querySelector("[data-password-toggle]");
    const input = document.getElementById("accessPassword");

    if (!toggle || !input) return;

    toggle.addEventListener("click", () => {
        input.type = input.type === "password" ? "text" : "password";
    });
});

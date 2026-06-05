document.addEventListener("click", function (e) {
    const logo = e.target.closest(".md-header__button.md-logo");

    if (!logo) return;

    e.preventDefault();

    // remove existing modal if any
    const old = document.getElementById("logo-modal");
    if (old) old.remove();

    const modal = document.createElement("div");
    modal.id = "logo-modal";

    modal.style.position = "fixed";
    modal.style.top = "0";
    modal.style.left = "0";
    modal.style.width = "100vw";
    modal.style.height = "100vh";
    modal.style.background = "rgba(0,0,0,0.96)";
    modal.style.display = "flex";
    modal.style.alignItems = "center";
    modal.style.justifyContent = "center";
    modal.style.zIndex = "999999";
    modal.style.cursor = "zoom-out";

    modal.innerHTML = `
        <img src="images/logo.png" id="logo-full"
             style="
                width: min(80vh, 80vw);
                height: min(80vh, 80vw);
                border-radius: 50%;
                object-fit: cover;
                box-shadow: 0 0 50px rgba(0,229,255,0.4);
             ">
    `;

    document.body.appendChild(modal);

    modal.addEventListener("click", function () {
        modal.remove();
    });
});
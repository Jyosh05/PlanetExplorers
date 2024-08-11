document.addEventListener("DOMContentLoaded", function () {
    const seeMoreLink = document.getElementById("see-more-link");
    const hiddenModules = document.querySelectorAll("#module-list .module-item[data-hidden='true']");

    seeMoreLink.addEventListener("click", function (event) {
        event.preventDefault(); // Prevent the default link action

        if (seeMoreLink.textContent.trim() === "See more") {
            hiddenModules.forEach(function (module) {
                module.style.display = "flex"; // Show the hidden modules
            });
            seeMoreLink.textContent = "See less"; // Change the text to "See less"
        } else {
            hiddenModules.forEach(function (module) {
                module.style.display = "none"; // Hide the extra modules
            });
            seeMoreLink.textContent = "See more"; // Change the text back to "See more"
        }
    });
});

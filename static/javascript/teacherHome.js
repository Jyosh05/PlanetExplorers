document.addEventListener("DOMContentLoaded", function () {
    const seeMoreLink = document.getElementById("see-more-link");
    const moduleItems = document.querySelectorAll("#module-list .module-item");

    function updateModuleVisibility() {
        moduleItems.forEach(function (module, index) {
            if (index >= 3) {
                module.style.display = module.getAttribute('data-hidden') === 'true' ? 'none' : 'flex';
            }
        });
    }

    seeMoreLink.addEventListener("click", function (event) {
        event.preventDefault(); // Prevent the default link action

        if (seeMoreLink.textContent.trim() === "See more") {
            moduleItems.forEach(function (module) {
                module.removeAttribute('data-hidden'); // Remove the data-hidden attribute
            });
            seeMoreLink.textContent = "See less"; // Change the text to "See less"
        } else {
            moduleItems.forEach(function (module, index) {
                if (index >= 3) {
                    module.setAttribute('data-hidden', 'true'); // Set the data-hidden attribute
                }
            });
            seeMoreLink.textContent = "See more"; // Change the text back to "See more"
        }
        updateModuleVisibility(); // Update visibility based on current state
    });

    // Handle clicks on module items
    moduleItems.forEach(function (item) {
        item.addEventListener('click', function () {
            var url = this.getAttribute('data-url').replace(/%7D/g, '}'); // Replace %7D with }
            window.location.href = url;
        });
    });

    updateModuleVisibility(); // Initial setup of visibility
});

function checkPasswordStrength() {
    var password = document.getElementById("password").value;
    var feedback = document.getElementById("password-feedback");
    var strengthBar = document.getElementById("password-strength-bar");
    var nextButton = document.getElementById("next-button");

    // Clear previous feedback and strength bar
    feedback.innerHTML = "";
    strengthBar.style.width = "0%";
    strengthBar.style.backgroundColor = "#FF5656"; // Reset to default color

    // Check if the password field is empty
    if (password.trim() === "") {
        nextButton.disabled = true; // Ensure the button stays disabled
        return; // Exit the function early if password is empty
    }

    // Define criteria
    var criteria = [
        { regex: /.{8,}/, message: "Must be at least 8 characters long" },
        { regex: /[a-z]/, message: "Contain at least one lowercase letter" },
        { regex: /[A-Z]/, message: "Contain at least one uppercase letter" },
        { regex: /\d/, message: "Contain at least one number" },
        { regex: /[@$!%*?&]/, message: "Contain at least one special character" }
    ];

    var strength = 0;

    // Create a list for error messages
    var errorList = document.createElement("ul");
    errorList.id = "error-messages";

    // Check each criterion
    criteria.forEach(function(criterion) {
        if (criterion.regex.test(password)) {
            strength += 20; // Increase strength by 20% per fulfilled criterion
        } else {
            // Create and append a list item for each unmet criterion
            var errorMessage = document.createElement("li");
            errorMessage.textContent = criterion.message;
            errorMessage.classList.add("error-message");
            errorList.appendChild(errorMessage);
        }
    });

    // Add the error list to the feedback area
    feedback.appendChild(errorList);

    // Update the width of the strength bar
    strengthBar.style.width = strength + "%";

    // Adjust color based on strength
    if (strength < 40) {
        strengthBar.style.backgroundColor = "#FF5656"; // Weak
    } else if (strength < 80) {
        strengthBar.style.backgroundColor = "#F9A825"; // Medium
    } else {
        strengthBar.style.backgroundColor = "#4CAF50"; // Strong
    }

    // Display overall message
    var overallMessage = document.createElement("p");
    overallMessage.classList.add("overall-feedback");

    if (strength >= 100) {
        overallMessage.textContent = "Password is strong";
        overallMessage.style.color = "#4CAF50"; // Strong color
        nextButton.disabled = false; // Enable the Next button
    } else {
        overallMessage.textContent = "Password does not meet requirements";
        overallMessage.style.color = "#FF5656"; // Weak color
        nextButton.disabled = true; // Disable the Next button
    }

    feedback.insertBefore(overallMessage, feedback.firstChild);
}

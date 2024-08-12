function goToPart2() {
    document.getElementById("part1").style.display = "none";
    document.getElementById("part2").style.display = "block";
}

function goToPart1() {
    document.getElementById("part2").style.display = "none";
    document.getElementById("part1").style.display = "block";
}

function submitForm() {
    // Combine form data from both parts
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    var email = document.getElementById("email").value;
    var name = document.getElementById("name").value;
    var age = document.getElementById("age").value;
    var address = document.getElementById("address").value;
    var phone = document.getElementById("phone").value;

    // Set values for part 1 fields (hidden fields)
    document.getElementById("username").value = username;
    document.getElementById("password").value = password;
    document.getElementById("email").value = email;

    // Check if the user wants to register as a teacher
    var registerAsTeacher = document.getElementById("register_as_teacher").checked;

    if (registerAsTeacher) {
        // Change the form action to the teacher registration endpoint
        document.getElementById("registrationForm").action = "/teacher_register";
    } else {
        // Change the form action to the student registration endpoint
        document.getElementById("registrationForm").action = "/register";
    }

    // Submit the form
    document.getElementById("registrationForm").submit();
}


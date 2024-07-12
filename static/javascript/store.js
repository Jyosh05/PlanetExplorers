document.addEventListener("DOMContentLoaded", function() {
    const quantityFields = document.querySelectorAll('.quantity-field');
    const plusButtons = document.querySelectorAll('.plus-btn');
    const minusButtons = document.querySelectorAll('.minus-btn');

    plusButtons.forEach((button, index) => {
        button.addEventListener('click', function() {
            let currentValue = parseInt(quantityFields[index].value);
            quantityFields[index].value = currentValue + 1;
        });
    });

    minusButtons.forEach((button, index) => {
        button.addEventListener('click', function() {
            let currentValue = parseInt(quantityFields[index].value);
            if (currentValue > 1) {
                quantityFields[index].value = currentValue - 1;
            }
        });
    });
});

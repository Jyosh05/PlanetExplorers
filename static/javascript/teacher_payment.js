document.addEventListener('DOMContentLoaded', () => {
    let cardNumInput = document.querySelector('#cardNum');

    cardNumInput.addEventListener('keyup', () => {
        let cNumber = cardNumInput.value;
        cNumber = cNumber.replace(/\s/g, ""); // Remove all spaces

        // Add spaces for display but not for validation
        if (Number(cNumber)) {
            cNumber = cNumber.match(/.{1,4}/g);
            cNumber = cNumber.join(" ");
            cardNumInput.value = cNumber;
        }
    });
});

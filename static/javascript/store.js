document.addEventListener("DOMContentLoaded", function() {
    const quantityFields = document.querySelectorAll('.quantity-field');
    const plusButtons = document.querySelectorAll('.plus-btn');
    const minusButtons = document.querySelectorAll('.minus-btn');
    const productItems = document.querySelectorAll('.product-item');
    const popup = document.getElementById('product-popup');
    const closeBtn = document.querySelector('.close-btn');
    const addToCartForm = document.getElementById('add-to-cart-form');

    productItems.forEach(item => {
        item.addEventListener('click', function() {
            const id = item.getAttribute('data-id');
            const name = item.getAttribute('data-name');
            const description = item.getAttribute('data-description');
            const price = item.getAttribute('data-price');
            const price_in_points = item.getAttribute('data-price_in_points');
            const image = item.getAttribute('data-image');

            document.getElementById('popup-product-id').value = id;
            document.getElementById('popup-name').innerText = name;
            document.getElementById('popup-description').innerText = description;
            document.getElementById('popup-price').innerText = `Price: $${price}`;
            document.getElementById('popup-price_in_points').innerText = `Explorer Points: ${price_in_points}`;
            document.getElementById('popup-image').src = image;

            popup.style.display = 'flex';
        });
    });

    closeBtn.addEventListener('click', function() {
        popup.style.display = 'none';
    });

    window.addEventListener('click', function(event) {
        if (event.target == popup) {
            popup.style.display = 'none';
        }
    });

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

    addToCartForm.addEventListener('submit', function(event) {
        event.preventDefault();

        const formData = new FormData(addToCartForm);
        const productId = formData.get('product_id');
        const quantity = formData.get('quantity');

        fetch(`/add_to_cart/${productId}`, {
            method: 'POST',
            body: new URLSearchParams(formData),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message);
            } else {
                alert(data.error);
            }
            popup.style.display = 'none';
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});

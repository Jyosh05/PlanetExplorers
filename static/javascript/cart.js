document.addEventListener("DOMContentLoaded", function() {
    const cartItems = document.querySelectorAll('.cart-item');
    const totalItemsElement = document.getElementById('total-items');
    const totalPriceInPointsElement = document.getElementById('total-price-in-points');
    const checkoutButton = document.getElementById('checkout-button');
    const paymentMethodElements = document.getElementsByName('paymentMethod');

    cartItems.forEach(item => {
        const minusBtn = item.querySelector('.minus-btn');
        const plusBtn = item.querySelector('.plus-btn');
        const removeBtn = item.querySelector('.remove-btn');
        const quantityField = item.querySelector('.quantity-field');

        minusBtn.addEventListener('click', function() {
            updateQuantity(item, -1);
        });

        plusBtn.addEventListener('click', function() {
            updateQuantity(item, 1);
        });

        removeBtn.addEventListener('click', function() {
            removeItem(item);
        });
    });

    function updateQuantity(item, delta) {
        const productId = item.getAttribute('data-id');
        const currentQuantity = parseInt(item.querySelector('.quantity-field').value);
        const newQuantity = currentQuantity + delta;

        if (newQuantity > 0) {
            fetch(`/update_cart/${productId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ quantity: newQuantity })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    item.querySelector('.quantity-field').value = newQuantity;
                    item.querySelector('.item-price_in_points').textContent = `Explorer Points: ${data.item_price_in_points}`;
                    totalItemsElement.textContent = data.total_items;
                    totalPriceInPointsElement.textContent = data.total_price_in_points;
                }
            });
        }
    }

    function removeItem(item) {
        const productId = item.getAttribute('data-id');

        fetch(`/remove_from_cart/${productId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                item.remove();
                totalItemsElement.textContent = data.total_items;
                totalPriceInPointsElement.textContent = data.total_price_in_points;
            }
        });
    }

    checkoutButton.addEventListener('click', function() {
        let selectedPaymentMethod = 'tokens';
        paymentMethodElements.forEach(method => {
            if (method.checked) {
                selectedPaymentMethod = method.value;
            }
        });

        if (selectedPaymentMethod === 'tokens') {
            window.location.href = '/payment_points';
        }
    });
});


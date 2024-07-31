document.addEventListener("DOMContentLoaded", function() {
    const totalPointsElement = document.getElementById('total-points');
    const shippingOptionElement = document.getElementById('shippingOption');
    const checkoutButton = document.getElementById('checkout-button');
    const paymentMethodElements = document.getElementsByName('paymentMethod');

    // Function to update the total points displayed
    function updateTotalPoints() {
        const shippingOption = shippingOptionElement.selectedOptions[0];
        const shippingCost = parseFloat(shippingOption.getAttribute('data-price')) || 0;
        const initialTotalPoints = parseFloat(totalPointsElement.dataset.initialTotalPoints) || 0;
        const updatedTotalPoints = initialTotalPoints + shippingCost;

        totalPointsElement.textContent = updatedTotalPoints.toFixed(2); // Update the total points display
    }

    // Function to update quantity and total points
    function updateQuantity(item, delta) {
        const productId = item.getAttribute('data-id');
        const quantityField = item.querySelector('.quantity-field');
        const currentQuantity = parseInt(quantityField.value);
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
                    quantityField.value = newQuantity;
                    item.querySelector('.item-price_in_points').textContent = `Explorer Points: ${data.item_price_in_points}`;
                    document.getElementById('total-items').textContent = data.total_items;
                    document.getElementById('total-price-in-points').textContent = data.total_price_in_points;
                    updateTotalPoints(); // Update total points after quantity change
                }
            });
        }
    }

    // Function to remove item and update totals
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
                document.getElementById('total-items').textContent = data.total_items;
                document.getElementById('total-price-in-points').textContent = data.total_price_in_points;
                updateTotalPoints(); // Update total points after item removal
            }
        });
    }

    // Event listeners for quantity update and item removal
    document.querySelectorAll('.cart-item').forEach(item => {
        const minusBtn = item.querySelector('.minus-btn');
        const plusBtn = item.querySelector('.plus-btn');
        const removeBtn = item.querySelector('.remove-btn');

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

    // Event listener for shipping option change
    if (shippingOptionElement) {
        shippingOptionElement.addEventListener('change', updateTotalPoints);
    }

    // Event listener for checkout button click
    if (checkoutButton) {
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
    }

    // Set initial total points and update on page load
    if (totalPointsElement) {
        totalPointsElement.dataset.initialTotalPoints = totalPointsElement.textContent;
        updateTotalPoints(); // Initial update to account for current shipping selection
    }
});



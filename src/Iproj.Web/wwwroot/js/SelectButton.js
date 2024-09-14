document.querySelectorAll('.button-toggle').forEach(button => {
    button.addEventListener('click', function (event) {
        event.preventDefault(); // Prevent form submission on click
        document.querySelectorAll('.button-toggle').forEach(btn => {
            btn.classList.remove('active'); // Remove active class from all buttons
        });
        this.classList.add('active'); // Add active class to clicked button
    });
});

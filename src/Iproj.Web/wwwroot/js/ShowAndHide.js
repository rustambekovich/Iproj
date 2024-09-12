document.addEventListener('DOMContentLoaded', (event) => {
    console.log('DOM fully loaded and parsed');
    const togglePassword = document.querySelector('#togglePassword');
    const password = document.querySelector('#password');
    const toggleIcon = document.querySelector('#toggleIcon');

    togglePassword.addEventListener('click', function () {

        const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
        password.setAttribute('type', type);

        if (type === 'password') {
            toggleIcon.src = "eye-removebg-preview.png"; 
        } else {
            toggleIcon.src = "hidden-removebg-preview.png"; 
        }

        console.log('Password visibility toggled');
    });
});

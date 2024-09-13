document.addEventListener('DOMContentLoaded', (event) => {
    console.log('DOM fully loaded and parsed');
    const togglePassword = document.querySelector('#togglePassword');
    const password = document.querySelector('#password');
    const eyeOpen = document.querySelector('#eyeOpen');
    const eyeClose = document.querySelector('#eyeClose');

    togglePassword.addEventListener('click', function () {
        const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
        password.setAttribute('type', type);

        // Toggle visibility of the eye icons
        if (type === 'password') {
            eyeOpen.style.display = 'block';
            eyeClose.style.display = 'none';
        } else {
            eyeOpen.style.display = 'none';
            eyeClose.style.display = 'block';
        }

        console.log('Password visibility toggled');
    });
});

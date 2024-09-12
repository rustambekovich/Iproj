document.addEventListener('DOMContentLoaded', (event) => {
    console.log('DOM fully loaded and parsed');
    const togglePassword = document.querySelector('#togglePassword');
    const password = document.querySelector('#password');
    const eyePath = document.querySelector('#eyePath'); 

    togglePassword.addEventListener('click', function () {
        const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
        password.setAttribute('type', type);

        if (type === 'password') {
            eyePath.setAttribute("d", "M12 4.5C7.5 4.5 3.7 7.5 2 12C3.7 16.5 7.5 19.5 12 19.5C16.5 19.5 20.3 16.5 22 12C20.3 7.5 16.5 4.5 12 4.5ZM12 17C8.8 17 6.1 14.8 5 12C6.1 9.2 8.8 7 12 7C15.2 7 17.9 9.2 19 12C17.9 14.8 15.2 17 12 17ZM12 9.5C10.6 9.5 9.5 10.6 9.5 12C9.5 13.4 10.6 14.5 12 14.5C13.4 14.5 14.5 13.4 14.5 12C14.5 10.6 13.4 9.5 12 9.5Z");
        } else {
            eyePath.setAttribute("d", "M17.94 17.94C16.14 19.06 14.16 19.73 12 19.73C7.2 19.73 3.18 16.19 1.5 12C2.36 9.76 4.18 7.95 6.39 6.84L3.5 3.94L4.94 2.5L19.5 17.06L17.94 17.94ZM12 17.73C14.5 17.73 16.73 16.58 18.44 14.73L14.68 10.97C14.47 11.07 14.24 11.14 14 11.14C12.84 11.14 12 10.3 12 9.14C12 8.89 12.06 8.66 12.16 8.45L9.11 5.39C7.02 6.35 5.47 7.83 4.68 9.73C6.22 12.71 8.89 14.73 12 14.73Z");
        }

        console.log('Password visibility toggled');
    });
});

document.addEventListener('DOMContentLoaded', function () {
    // Function to toggle visibility
    function togglePasswordVisibility(inputId, eyeOpenId, eyeCloseId) {
        const passwordInput = document.getElementById(inputId);
        const eyeOpen = document.getElementById(eyeOpenId);
        const eyeClose = document.getElementById(eyeCloseId);

        eyeOpen.addEventListener('click', function () {
            passwordInput.type = 'text';
            eyeOpen.style.display = 'none';
            eyeClose.style.display = 'block';
        });

        eyeClose.addEventListener('click', function () {
            passwordInput.type = 'password';
            eyeOpen.style.display = 'block';
            eyeClose.style.display = 'none';
        });
    }

    // Initialize toggling for each password field
    togglePasswordVisibility('oldPassword', 'eyeOpenOld', 'eyeCloseOld');
    togglePasswordVisibility('newPassword', 'eyeOpenNew', 'eyeCloseNew');
    togglePasswordVisibility('confirmNewPassword', 'eyeOpenConfrm', 'eyeCloseConfrm');
});

$(document).ready(function () {

    $('#profileImage').on('click', function () {
        $(this).next('.dropdown-menu').toggleClass('show');
    });

    $(document).on('click', function (event) {
        if (!$(event.target).closest('.dropdown').length) {
            $('.dropdown-menu').removeClass('show');
        }
    });

});
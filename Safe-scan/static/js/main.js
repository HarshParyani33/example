document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const resultPre = document.querySelector('pre');

    form.addEventListener('submit', function() {
        if (resultPre) {
            resultPre.textContent = "Scanning... please wait!";
        }
    });
});

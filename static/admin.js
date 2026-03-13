document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      var msg = el.getAttribute('data-confirm');
      if (!confirm(msg)) {
        e.preventDefault();
      }
    });
  });

  var copyBtn = document.querySelector('[data-copy-key]');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var val = document.getElementById('new-api-key-value').textContent.trim();
      navigator.clipboard.writeText(val).then(function () {
        copyBtn.textContent = 'Copied';
        setTimeout(function () { copyBtn.textContent = 'Copy'; }, 2000);
      });
    });
  }
});

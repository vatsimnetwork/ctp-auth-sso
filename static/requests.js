document.addEventListener('DOMContentLoaded', function () {
  var modal = document.getElementById('request-modal');
  if (!modal) return;

  var openBtn = document.getElementById('request-access-btn');
  var closeBtn = document.getElementById('request-modal-close');
  var backdrop = document.getElementById('request-modal-backdrop');

  function openModal() { modal.classList.remove('hidden'); }
  function closeModal() { modal.classList.add('hidden'); }

  if (openBtn) openBtn.addEventListener('click', openModal);
  closeBtn.addEventListener('click', closeModal);
  backdrop.addEventListener('click', closeModal);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeModal();
  });
});

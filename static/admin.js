document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-toggle]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      if (e.target.closest('form')) return;
      var target = document.getElementById(el.getAttribute('data-toggle'));
      if (target) target.classList.toggle('hidden');
    });
  });

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

  var modal = document.getElementById('role-modal');
  var modalCidLabel = document.getElementById('role-modal-cid-label');
  var modalCidInput = document.getElementById('role-modal-cid-input');
  var modalCheckboxes = document.getElementById('role-modal-checkboxes');
  var editBtn = document.getElementById('edit-roles-btn');
  var roleDataEl = document.getElementById('role-data');
  var ALL_ROLES = roleDataEl ? JSON.parse(roleDataEl.getAttribute('data-roles') || '[]') : [];

  var bulkModal = document.getElementById('bulk-modal');

  function closeModal() { modal.classList.add('hidden'); }
  function closeBulkModal() { if (bulkModal) bulkModal.classList.add('hidden'); }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { closeModal(); closeBulkModal(); }
  });

  if (editBtn) {
    document.getElementById('role-modal-close').addEventListener('click', closeModal);
    document.getElementById('role-modal-backdrop').addEventListener('click', closeModal);

    editBtn.addEventListener('click', function () {
      var cid = document.getElementById('manage-cid').value.trim();
      if (!cid || !/^\d+$/.test(cid)) return;

      fetch('/admin/users/roles?cid=' + encodeURIComponent(cid))
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var current = data.roles || [];
          modalCidLabel.textContent = cid;
          modalCidInput.value = cid;
          modalCheckboxes.innerHTML = '';

          if (!ALL_ROLES.length) {
            var msg = document.createElement('span');
            msg.className = 'block px-4 py-2 text-xs text-ap-muted dark:text-gp-muted';
            msg.textContent = 'No roles yet.';
            modalCheckboxes.appendChild(msg);
          } else {
            ALL_ROLES.forEach(function (name) {
              var label = document.createElement('label');
              label.className = 'flex items-center justify-between px-4 py-2 cursor-pointer select-none';
              var span = document.createElement('span');
              span.className = 'text-sm text-ap-text dark:text-gp-text';
              span.textContent = name;
              var cb = document.createElement('input');
              cb.type = 'checkbox';
              cb.name = 'role';
              cb.value = name;
              cb.className = 'w-3.5 h-3.5 accent-ap-primary dark:accent-gp-primary cursor-pointer';
              cb.checked = current.indexOf(name) !== -1;
              label.appendChild(span);
              label.appendChild(cb);
              modalCheckboxes.appendChild(label);
            });
          }

          modal.classList.remove('hidden');
        })
        .catch(function (err) { console.error('role fetch failed', err); });
    });
  }

  var bulkAddBtn = document.getElementById('bulk-add-btn');

  if (bulkAddBtn) {
    var bulkCidInput = document.getElementById('bulk-cid-input');
    var bulkCidList = document.getElementById('bulk-cid-list');
    var bulkCids = [];

    document.getElementById('bulk-modal-close').addEventListener('click', closeBulkModal);
    document.getElementById('bulk-modal-backdrop').addEventListener('click', closeBulkModal);

    function renderBulkList() {
      bulkCidList.innerHTML = '';
      bulkCids.forEach(function (cid) {
        var row = document.createElement('div');
        row.className = 'flex items-center justify-between px-4 py-2';
        var hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = 'cid';
        hidden.value = cid;
        var span = document.createElement('span');
        span.className = 'text-sm font-mono text-ap-text dark:text-gp-text';
        span.textContent = cid;
        var removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'text-xs text-ap-muted dark:text-gp-muted hover:text-red-500 dark:hover:text-red-400 transition-colors duration-100';
        removeBtn.textContent = 'Remove';
        removeBtn.addEventListener('click', function () {
          bulkCids.splice(bulkCids.indexOf(cid), 1);
          renderBulkList();
        });
        row.appendChild(hidden);
        row.appendChild(span);
        row.appendChild(removeBtn);
        bulkCidList.appendChild(row);
      });
    }

    function addBulkCid(raw) {
      var cid = raw.trim();
      if (!cid || !/^\d+$/.test(cid) || cid.length > 20) return;
      if (bulkCids.indexOf(cid) !== -1) return;
      bulkCids.push(cid);
      renderBulkList();
    }

    function commitBulkInput() {
      var val = bulkCidInput.value.trim();
      if (val) { addBulkCid(val); bulkCidInput.value = ''; }
    }

    document.getElementById('bulk-cid-add-btn').addEventListener('click', commitBulkInput);

    bulkCidInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); commitBulkInput(); }
    });

    bulkCidInput.addEventListener('input', function () {
      var val = bulkCidInput.value;
      if (val.indexOf(',') === -1) return;
      var parts = val.split(',');
      for (var i = 0; i < parts.length - 1; i++) addBulkCid(parts[i]);
      bulkCidInput.value = parts[parts.length - 1].trimStart();
    });

    bulkAddBtn.addEventListener('click', function () {
      var role = document.getElementById('bulk-role').value;
      if (!role) return;
      bulkCids = [];
      bulkCidInput.value = '';
      renderBulkList();
      document.getElementById('bulk-modal-role-label').textContent = role;
      document.getElementById('bulk-modal-role-input').value = role;
      bulkModal.classList.remove('hidden');
      bulkCidInput.focus();
    });
  }
});

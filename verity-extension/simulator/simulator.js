document.addEventListener('DOMContentLoaded', () => {
  const resultBox = document.getElementById('result-box');
  const attackUrlInput = document.getElementById('attack-url');
  const copyBtn = document.getElementById('copy-btn');
  
  document.querySelectorAll('.demo-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const url = e.target.getAttribute('data-url');
      if (url) {
        attackUrlInput.value = url;
        resultBox.classList.remove('hidden');
        
        copyBtn.textContent = 'Copy';
        copyBtn.classList.remove('verity-btn-danger');
        copyBtn.classList.add('verity-btn-primary');
      }
    });
  });

  copyBtn.addEventListener('click', () => {
    attackUrlInput.select();
    document.execCommand('copy');
    copyBtn.textContent = 'Copied!';
    copyBtn.classList.remove('verity-btn-primary');
    copyBtn.classList.add('verity-btn-danger');
  });
});

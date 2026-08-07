document.addEventListener('DOMContentLoaded', async () => {
  const select = document.getElementById('brand-select');
  const generateBtn = document.getElementById('generate-btn');
  const resultBox = document.getElementById('result-box');
  const attackUrlInput = document.getElementById('attack-url');
  const copyBtn = document.getElementById('copy-btn');
  
  let brandsList = [];

  try {
    const res = await fetch(chrome.runtime.getURL('brands.json'));
    brandsList = await res.json();
    
    select.innerHTML = '<option value="" disabled selected>Select a brand...</option>';
    
    // Pin top brands
    const pinnedNames = ['PayPal', 'Chase', 'Amazon'];
    const pinned = [];
    const others = [];
    
    for (const b of brandsList) {
      if (pinnedNames.includes(b.name)) {
        pinned.push(b);
      } else {
        others.push(b);
      }
    }
    
    // Sort pinned to maintain order, sort others alphabetically
    pinned.sort((a,b) => pinnedNames.indexOf(a.name) - pinnedNames.indexOf(b.name));
    others.sort((a,b) => a.name.localeCompare(b.name));
    
    const combined = [...pinned, ...others];
    
    combined.forEach((brand, index) => {
      const opt = document.createElement('option');
      opt.value = index.toString(); // reference index in combined array
      opt.textContent = brand.name;
      select.appendChild(opt);
    });
    
    select.addEventListener('change', () => {
      if (select.value !== "") {
        generateBtn.disabled = false;
        resultBox.classList.add('hidden');
      }
    });

    generateBtn.addEventListener('click', () => {
      const idx = parseInt(select.value, 10);
      const brand = combined[idx];
      
      // Select a random variant
      let variant = brand.name.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (brand.variants && brand.variants.length > 0) {
        variant = brand.variants[Math.floor(Math.random() * brand.variants.length)];
      }
      
      const port = 8123;
      const url = `http://${variant}.localhost:${port}/`;
      
      attackUrlInput.value = url;
      resultBox.classList.remove('hidden');
      
      copyBtn.textContent = 'Copy';
      copyBtn.classList.remove('verity-btn-danger');
      copyBtn.classList.add('verity-btn-primary');
    });

    copyBtn.addEventListener('click', () => {
      attackUrlInput.select();
      document.execCommand('copy');
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.remove('verity-btn-primary');
      copyBtn.classList.add('verity-btn-danger');
    });

  } catch (err) {
    console.error(err);
    select.innerHTML = '<option value="" disabled>Error loading brands</option>';
  }
});

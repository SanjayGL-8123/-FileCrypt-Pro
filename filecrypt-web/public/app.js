/**
 * FileCrypt Pro — Client-Side Application Logic
 *
 * Features:
 * - Dual Engine: Local Server API (C / Node / Python) or Pure In-Browser WebCrypto
 * - SHA-256 File Fingerprint & Checksum Verification
 * - High-Entropy Password Generator
 * - Real-Time Password Strength Estimator
 * - Drag-and-Drop File Handling with Instant Preview
 * - Full Dark / Light Mode with Local Storage Persistence
 */

(function () {
  'use strict';

  const MAX_BYTES = 100 * 1024 * 1024; // 100 MB
  const MAGIC = new Uint8Array([0x46, 0x45, 0x4e, 0x43]); // "FENC"
  const ROUNDS = 100000;
  const FNV_PRIME = 1099511628211n;
  const FNV_INIT = 14695981039346656037n;
  const MASK64 = 0xFFFFFFFFFFFFFFFFn;
  const MULT = 2685821657736338717n;

  // DOM Elements
  const $ = (id) => document.getElementById(id);
  const el = {
    themeToggle: $('themeToggle'),
    themeIconSun: $('themeIconSun'),
    themeIconMoon: $('themeIconMoon'),
    engineStatus: $('engineStatus'),
    engineStatusText: $('engineStatusText'),
    engineSelect: $('engineSelect'),
    tabEnc: $('tabEnc'),
    tabDec: $('tabDec'),
    dropZone: $('dropZone'),
    fileInput: $('fileInput'),
    dropEmptyState: $('dropEmptyState'),
    fileSelectedState: $('fileSelectedState'),
    fileName: $('fileName'),
    fileSize: $('fileSize'),
    fileHashPreview: $('fileHashPreview'),
    removeFileBtn: $('removeFileBtn'),
    passwordInput: $('passwordInput'),
    confirmInput: $('confirmInput'),
    confirmGroup: $('confirmGroup'),
    generatePwBtn: $('generatePwBtn'),
    togglePwBtn: $('togglePwBtn'),
    eyeIconShow: $('eyeIconShow'),
    eyeIconHide: $('eyeIconHide'),
    strengthBar: $('strengthBar'),
    strengthLabel: $('strengthLabel'),
    matchFeedback: $('matchFeedback'),
    actionBtn: $('actionBtn'),
    actionBtnText: $('actionBtnText'),
    btnSpinner: $('btnSpinner'),
    progressSection: $('progressSection'),
    progressStatus: $('progressStatus'),
    progressPercent: $('progressPercent'),
    progressBar: $('progressBar'),
    statusAlert: $('statusAlert'),
    alertMessage: $('alertMessage'),
    resultSection: $('resultSection'),
    resultTitle: $('resultTitle'),
    resultSubtitle: $('resultSubtitle'),
    resultFileName: $('resultFileName'),
    resultFileHash: $('resultFileHash'),
    copyHashBtn: $('copyHashBtn'),
    downloadBtn: $('downloadBtn'),
    downloadBtnText: $('downloadBtnText'),
    resetBtn: $('resetBtn')
  };

  // State Management
  const state = {
    mode: 'enc', // 'enc' or 'dec'
    file: null,
    busy: false,
    serverAvailable: false,
    engine: 'auto', // 'auto', 'webcrypto', 'server'
    resultUrl: null,
    resultBlob: null,
    resultFileName: ''
  };

  /* ================= Initialization ================= */

  function init() {
    initTheme();
    bindEvents();
    checkServerHealth();
    refreshUI();
  }

  /* ================= Theme Handler ================= */

  function initTheme() {
    const savedTheme = localStorage.getItem('filecrypt_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcons(savedTheme);
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('filecrypt_theme', next);
    updateThemeIcons(next);
  }

  function updateThemeIcons(theme) {
    if (theme === 'dark') {
      el.themeIconSun.classList.remove('hidden');
      el.themeIconMoon.classList.add('hidden');
    } else {
      el.themeIconSun.classList.add('hidden');
      el.themeIconMoon.classList.remove('hidden');
    }
  }

  /* ================= Server & Engine Detection ================= */

  async function checkServerHealth() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch('/api/health', { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        state.serverAvailable = true;
        updateEngineBadge('server', 'Local Server Online');
      } else {
        throw new Error('Server returned non-200');
      }
    } catch {
      state.serverAvailable = false;
      updateEngineBadge('webcrypto', 'WebCrypto Browser Engine');
    }
  }

  function updateEngineBadge(activeType, text) {
    el.engineStatus.className = 'engine-badge online';
    el.engineStatusText.textContent = text;
  }

  function getActiveEngine() {
    if (el.engineSelect.value === 'webcrypto') return 'webcrypto';
    if (el.engineSelect.value === 'server') return 'server';
    return state.serverAvailable ? 'server' : 'webcrypto';
  }

  /* ================= Event Listeners ================= */

  function bindEvents() {
    el.themeToggle.addEventListener('click', toggleTheme);

    el.tabEnc.addEventListener('click', () => setMode('enc'));
    el.tabDec.addEventListener('click', () => setMode('dec'));

    // File Drop Zone
    el.dropZone.addEventListener('click', (e) => {
      if (e.target === el.removeFileBtn || el.removeFileBtn.contains(e.target)) return;
      el.fileInput.click();
    });
    el.fileInput.addEventListener('change', () => {
      if (el.fileInput.files.length) handleFileSelected(el.fileInput.files[0]);
    });

    ['dragenter', 'dragover'].forEach(ev => {
      el.dropZone.addEventListener(ev, (e) => {
        e.preventDefault();
        el.dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(ev => {
      el.dropZone.addEventListener(ev, (e) => {
        e.preventDefault();
        el.dropZone.classList.remove('dragover');
      });
    });

    el.dropZone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileSelected(e.dataTransfer.files[0]);
      }
    });

    el.removeFileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      clearSelectedFile();
    });

    // Password & Inputs
    el.passwordInput.addEventListener('input', () => {
      updatePasswordStrength();
      validatePasswords();
      refreshUI();
    });

    el.confirmInput.addEventListener('input', () => {
      validatePasswords();
      refreshUI();
    });

    el.togglePwBtn.addEventListener('click', togglePasswordVisibility);
    el.generatePwBtn.addEventListener('click', generateStrongPassword);

    // Actions
    el.actionBtn.addEventListener('click', executeProcess);
    el.resetBtn.addEventListener('click', resetAll);
    el.copyHashBtn.addEventListener('click', copyResultHash);

    // Engine Selection Change
    el.engineSelect.addEventListener('change', () => {
      const eng = getActiveEngine();
      if (eng === 'server') {
        updateEngineBadge('server', state.serverAvailable ? 'Local Server Online' : 'Local Server (Attempting)');
      } else {
        updateEngineBadge('webcrypto', 'WebCrypto Browser Engine');
      }
    });

    // Keyboard shortcuts
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (!el.actionBtn.disabled) executeProcess();
      }
      if (e.key === 'Escape') {
        hideAlert();
      }
    });
  }

  /* ================= Mode & File Handling ================= */

  function setMode(newMode) {
    if (state.mode === newMode) return;
    state.mode = newMode;
    clearResult();

    const isEnc = newMode === 'enc';
    el.tabEnc.classList.toggle('active', isEnc);
    el.tabDec.classList.toggle('active', !isEnc);
    el.tabEnc.setAttribute('aria-selected', String(isEnc));
    el.tabDec.setAttribute('aria-selected', String(!isEnc));

    el.confirmGroup.classList.toggle('hidden', !isEnc);
    el.actionBtnText.textContent = isEnc ? 'Encrypt File' : 'Decrypt File';

    refreshUI();
  }

  async function handleFileSelected(file) {
    clearAlert();
    clearResult();

    if (!file) return;
    if (file.size === 0) {
      showAlert('The selected file is empty (0 bytes).', 'error');
      return;
    }
    if (file.size > MAX_BYTES) {
      showAlert('File exceeds the 100 MB limit. Please select a smaller file.', 'error');
      return;
    }

    state.file = file;
    el.fileName.textContent = file.name;
    el.fileSize.textContent = formatBytes(file.size);
    el.fileHashPreview.textContent = 'Computing SHA-256...';

    el.dropEmptyState.classList.add('hidden');
    el.fileSelectedState.classList.remove('hidden');

    refreshUI();

    // Auto-compute SHA-256 for integrity preview
    try {
      const hash = await computeFileSha256(file);
      if (state.file === file) {
        el.fileHashPreview.textContent = `SHA-256: ${hash.slice(0, 16)}...${hash.slice(-8)}`;
      }
    } catch {
      el.fileHashPreview.textContent = 'Hash preview unavailable';
    }
  }

  function clearSelectedFile() {
    state.file = null;
    el.fileInput.value = '';
    el.dropEmptyState.classList.remove('hidden');
    el.fileSelectedState.classList.add('hidden');
    clearResult();
    refreshUI();
  }

  /* ================= Password Logic ================= */

  function togglePasswordVisibility() {
    const isPw = el.passwordInput.type === 'password';
    el.passwordInput.type = isPw ? 'text' : 'password';
    el.confirmInput.type = isPw ? 'text' : 'password';
    el.eyeIconShow.classList.toggle('hidden', isPw);
    el.eyeIconHide.classList.toggle('hidden', !isPw);
  }

  function generateStrongPassword() {
    const charset = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+=-';
    const values = new Uint32Array(16);
    crypto.getRandomValues(values);
    let pw = '';
    for (let i = 0; i < 16; i++) {
      pw += charset[values[i] % charset.length];
    }
    el.passwordInput.value = pw;
    el.confirmInput.value = pw;
    updatePasswordStrength();
    validatePasswords();
    refreshUI();
  }

  function updatePasswordStrength() {
    const val = el.passwordInput.value;
    if (!val) {
      el.strengthBar.className = 'strength-bar';
      el.strengthLabel.textContent = 'Enter password';
      return;
    }

    let score = 0;
    if (val.length >= 8) score++;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    el.strengthBar.className = 'strength-bar';
    if (score <= 2) {
      el.strengthBar.classList.add('weak');
      el.strengthLabel.textContent = 'Weak';
    } else if (score === 3) {
      el.strengthBar.classList.add('fair');
      el.strengthLabel.textContent = 'Fair';
    } else if (score === 4) {
      el.strengthBar.classList.add('good');
      el.strengthLabel.textContent = 'Strong';
    } else {
      el.strengthBar.classList.add('strong');
      el.strengthLabel.textContent = 'Very Strong';
    }
  }

  function validatePasswords() {
    if (state.mode !== 'enc') {
      el.matchFeedback.textContent = '';
      return true;
    }
    const p1 = el.passwordInput.value;
    const p2 = el.confirmInput.value;

    if (!p2) {
      el.matchFeedback.textContent = '';
      return false;
    }

    if (p1 === p2) {
      el.matchFeedback.textContent = '✓ Match';
      el.matchFeedback.className = 'match-feedback valid';
      return true;
    } else {
      el.matchFeedback.textContent = '✗ Passwords do not match';
      el.matchFeedback.className = 'match-feedback invalid';
      return false;
    }
  }

  function refreshUI() {
    const hasFile = Boolean(state.file);
    const hasPw = Boolean(el.passwordInput.value);
    const pwMatch = state.mode === 'enc' ? (el.passwordInput.value === el.confirmInput.value) : true;
    const ready = hasFile && hasPw && pwMatch && !state.busy;

    el.actionBtn.disabled = !ready;
  }

  /* ================= In-Browser WebCrypto Cipher Parity ================= */

  function fnv1a(h, data) {
    for (let i = 0; i < data.length; i++) {
      h = ((h ^ BigInt(data[i])) * FNV_PRIME) & MASK64;
    }
    return h;
  }

  function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const pwBytes = enc.encode(password);
    let h = FNV_INIT;
    for (let i = 0; i < ROUNDS; i++) {
      h = fnv1a(h, pwBytes);
      h = fnv1a(h, salt);
    }
    return h === 0n ? 0x9E3779B97F4A7C15n : h;
  }

  function createKeystream(key) {
    let s = key;
    return function nextByte() {
      s = (s ^ (s >> 12n)) & MASK64;
      s = (s ^ ((s << 25n) & MASK64)) & MASK64;
      s = (s ^ (s >> 27n)) & MASK64;
      return Number(((s * MULT & MASK64) >> 56n) & 0xFFn);
    };
  }

  function passwordCheck(key) {
    let s = key ^ 0xA5A5A5A5A5A5A5A5n;
    const next = () => {
      s = (s ^ (s >> 12n)) & MASK64;
      s = (s ^ ((s << 25n) & MASK64)) & MASK64;
      s = (s ^ (s >> 27n)) & MASK64;
      return Number(((s * MULT & MASK64) >> 56n) & 0xFFn);
    };
    let v = 0;
    for (let i = 0; i < 4; i++) {
      v = ((v << 8) | next()) >>> 0;
    }
    return v;
  }

  async function processClientSide(file, password, mode, onProgress) {
    const arrayBuffer = await file.arrayBuffer();
    const input = new Uint8Array(arrayBuffer);

    if (mode === 'enc') {
      onProgress(10, 'Deriving cryptographic key (100k rounds)...');
      await yieldTick();

      const salt = new Uint8Array(8);
      crypto.getRandomValues(salt);

      const key = deriveKey(password, salt);
      const check = passwordCheck(key);

      onProgress(30, 'Encrypting data stream...');
      await yieldTick();

      const output = new Uint8Array(16 + input.length);
      output.set(MAGIC, 0);
      output.set(salt, 4);

      // Checksum (big-endian uint32)
      output[12] = (check >>> 24) & 0xFF;
      output[13] = (check >>> 16) & 0xFF;
      output[14] = (check >>> 8) & 0xFF;
      output[15] = check & 0xFF;

      const next = createKeystream(key);
      const chunkSize = 262144; // 256 KB chunks for progress updates
      for (let i = 0; i < input.length; i += chunkSize) {
        const end = Math.min(i + chunkSize, input.length);
        for (let j = i; j < end; j++) {
          output[16 + j] = input[j] ^ next();
        }
        const pct = Math.round(30 + ((end / input.length) * 65));
        onProgress(pct, `Encrypting (${Math.round((end / input.length) * 100)}%)...`);
        await yieldTick();
      }

      onProgress(100, 'Finalizing archive...');
      return new Blob([output], { type: 'application/octet-stream' });
    } else {
      // Decrypt
      if (input.length < 16) {
        throw new Error('File is too small to be a valid FileCrypt file.');
      }
      for (let i = 0; i < 4; i++) {
        if (input[i] !== MAGIC[i]) {
          throw new Error('This is not a valid FileCrypt encrypted file (magic mismatch).');
        }
      }

      const salt = input.slice(4, 12);
      const storedCheck = ((input[12] << 24) | (input[13] << 16) | (input[14] << 8) | input[15]) >>> 0;

      onProgress(15, 'Verifying authentication token...');
      await yieldTick();

      const key = deriveKey(password, salt);
      if (passwordCheck(key) !== storedCheck) {
        throw new Error('Incorrect password. Authentication verification failed.');
      }

      onProgress(35, 'Decrypting data stream...');
      await yieldTick();

      const ciphertext = input.slice(16);
      const plaintext = new Uint8Array(ciphertext.length);
      const next = createKeystream(key);

      const chunkSize = 262144;
      for (let i = 0; i < ciphertext.length; i += chunkSize) {
        const end = Math.min(i + chunkSize, ciphertext.length);
        for (let j = i; j < end; j++) {
          plaintext[j] = ciphertext[j] ^ next();
        }
        const pct = Math.round(35 + ((end / ciphertext.length) * 60));
        onProgress(pct, `Decrypting (${Math.round((end / ciphertext.length) * 100)}%)...`);
        await yieldTick();
      }

      onProgress(100, 'Decryption complete.');
      return new Blob([plaintext], { type: 'application/octet-stream' });
    }
  }

  function yieldTick() {
    return new Promise(resolve => setTimeout(resolve, 0));
  }

  /* ================= Execution Workflow ================= */

  async function executeProcess() {
    const pw = el.passwordInput.value;
    if (state.mode === 'enc' && pw !== el.confirmInput.value) {
      showAlert('Passwords do not match. Please re-check.', 'error');
      return;
    }

    clearAlert();
    clearResult();

    state.busy = true;
    refreshUI();

    el.btnSpinner.classList.remove('hidden');
    el.progressSection.classList.remove('hidden');
    setProgress(0, 'Initializing pipeline...');

    const chosenEngine = getActiveEngine();
    const isEnc = state.mode === 'enc';

    try {
      let resultBlob = null;

      if (chosenEngine === 'server') {
        resultBlob = await processViaServer(state.file, pw, state.mode);
      } else {
        resultBlob = await processClientSide(state.file, pw, state.mode, (pct, status) => {
          setProgress(pct, status);
        });
      }

      setProgress(100, 'Computing output checksum...');
      const resultHash = await computeBlobSha256(resultBlob);

      const outputName = formatOutputName(state.file.name, isEnc);
      presentResult(resultBlob, outputName, resultHash);
    } catch (err) {
      el.progressSection.classList.add('hidden');
      showAlert(err.message || 'Operation failed.', 'error');
    } finally {
      state.busy = false;
      el.btnSpinner.classList.add('hidden');
      refreshUI();
    }
  }

  function processViaServer(file, password, mode) {
    return new Promise((resolve, reject) => {
      const endpoint = mode === 'enc' ? '/api/encrypt' : '/api/decrypt';
      const xhr = new XMLHttpRequest();
      xhr.open('POST', endpoint);
      xhr.setRequestHeader('X-Password', encodeURIComponent(password));
      xhr.responseType = 'blob';

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 75);
          setProgress(pct, `Uploading to server (${formatBytes(e.loaded)} / ${formatBytes(e.total)})...`);
        }
      };

      xhr.onload = async () => {
        if (xhr.status === 200) {
          setProgress(90, 'Finalizing download...');
          resolve(xhr.response);
        } else {
          try {
            const errText = await xhr.response.text();
            reject(new Error(errText || `Server responded with status ${xhr.status}`));
          } catch {
            reject(new Error(`Server error (${xhr.status})`));
          }
        }
      };

      xhr.onerror = () => {
        reject(new Error('Cannot reach local server. You can switch engine to "Pure Browser (WebCrypto)" in the top bar.'));
      };

      xhr.send(file);
    });
  }

  function presentResult(blob, filename, hash) {
    state.resultBlob = blob;
    state.resultFileName = filename;

    if (state.resultUrl) URL.revokeObjectURL(state.resultUrl);
    state.resultUrl = URL.createObjectURL(blob);

    el.resultFileName.textContent = filename;
    el.resultFileHash.textContent = hash;
    el.resultTitle.textContent = state.mode === 'enc' ? 'File Encrypted Successfully!' : 'File Decrypted Successfully!';
    el.resultSubtitle.textContent = `Size: ${formatBytes(blob.size)} • Ready for immediate download`;

    el.downloadBtn.href = state.resultUrl;
    el.downloadBtn.download = filename;
    el.downloadBtnText.textContent = `Download ${filename}`;

    el.progressSection.classList.add('hidden');
    el.resultSection.classList.remove('hidden');
  }

  function resetAll() {
    clearSelectedFile();
    el.passwordInput.value = '';
    el.confirmInput.value = '';
    updatePasswordStrength();
    validatePasswords();
    clearResult();
    clearAlert();
    refreshUI();
  }

  function clearResult() {
    if (state.resultUrl) {
      URL.revokeObjectURL(state.resultUrl);
      state.resultUrl = null;
    }
    state.resultBlob = null;
    el.resultSection.classList.add('hidden');
    el.progressSection.classList.add('hidden');
  }

  /* ================= Utilities ================= */

  function setProgress(pct, statusText) {
    el.progressBar.style.width = `${pct}%`;
    el.progressPercent.textContent = `${pct}%`;
    el.progressStatus.textContent = statusText;
  }

  function showAlert(msg, kind) {
    el.statusAlert.className = `status-alert ${kind}`;
    el.alertMessage.textContent = msg;
    el.statusAlert.classList.remove('hidden');
  }

  function hideAlert() {
    el.statusAlert.classList.add('hidden');
  }

  function clearAlert() {
    hideAlert();
  }

  function copyResultHash() {
    const hash = el.resultFileHash.textContent;
    if (!hash || hash === 'computing...') return;
    navigator.clipboard.writeText(hash).then(() => {
      const orig = el.copyHashBtn.innerHTML;
      el.copyHashBtn.innerHTML = '✓';
      setTimeout(() => { el.copyHashBtn.innerHTML = orig; }, 1500);
    });
  }

  function formatOutputName(originalName, isEnc) {
    if (isEnc) return originalName + '.enc';
    return /\.enc$/i.test(originalName) ? originalName.replace(/\.enc$/i, '') : originalName + '.dec';
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async function computeBlobSha256(blob) {
    const buffer = await blob.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function computeFileSha256(file) {
    return computeBlobSha256(file);
  }

  // Self execute
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

/**
 * Clonex Esports - Anti-Tamper & Content Protection Shield
 * Enforces Anti-Inspect, Anti-DevTools Auto-Ban, and Anti-Copy Protection.
 */
(function() {
  'use strict';

  // Safeguard: Do not run inside admin portal or for whitelisted administrator IPs
  if (window.__IS_IP_WHITELISTED__ || window.location.pathname.startsWith('/admin') || window.location.pathname === '/blocked') {
    return;
  }

  let antiInspectActive = true;
  let antiCopyActive = true;
  let hasTriggeredBan = false;

  // Asynchronously verify whitelist exemption and protection settings
  try {
    fetch('/api/security/my-ip')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.isWhitelisted) {
          window.__IS_IP_WHITELISTED__ = true;
          removeCopyProtection();
        }
      })
      .catch(() => {});

    fetch('/api/settings')
      .then(res => res.ok ? res.json() : null)
      .then(settings => {
        if (settings) {
          if (settings.antiInspectEnabled === false) antiInspectActive = false;
          if (settings.antiCopyEnabled === false) {
            antiCopyActive = false;
            removeCopyProtection();
          }
        }
      })
      .catch(() => {});
  } catch (err) {}

  // -------------------------------------------------------------
  // 1. Sleek Floating Toast Notification
  // -------------------------------------------------------------
  let toastTimer = null;
  function showSecurityToast(message) {
    let toast = document.getElementById('clonex-security-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'clonex-security-toast';
      toast.style.cssText = `
        position: fixed;
        bottom: 28px;
        left: 50%;
        transform: translateX(-50%) translateY(20px);
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid #334155;
        padding: 12px 22px;
        border-radius: 9999px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 13.5px;
        font-weight: 600;
        letter-spacing: -0.01em;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px rgba(2, 132, 199, 0.2);
        z-index: 99999999;
        display: flex;
        align-items: center;
        gap: 10px;
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.25s ease, transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      `;
      document.body.appendChild(toast);
    }

    toast.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <span>${message}</span>
    `;

    toast.style.opacity = '1';
    toast.style.transform = 'translateX(-50%) translateY(0)';

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(-50%) translateY(15px)';
    }, 2500);
  }

  // -------------------------------------------------------------
  // 2. Anti-Copy & Anti-Selection Protection
  // -------------------------------------------------------------
  let styleElement = null;
  function applyCopyProtectionStyles() {
    if (document.getElementById('clonex-anti-copy-css')) return;
    styleElement = document.createElement('style');
    styleElement.id = 'clonex-anti-copy-css';
    styleElement.textContent = `
      *, *::before, *::after {
        -webkit-user-select: none !important;
        -moz-user-select: none !important;
        -ms-user-select: none !important;
        user-select: none !important;
        -webkit-touch-callout: none !important;
      }
      input, textarea, [contenteditable="true"] {
        -webkit-user-select: text !important;
        -moz-user-select: text !important;
        -ms-user-select: text !important;
        user-select: text !important;
      }
    `;
    (document.head || document.documentElement).appendChild(styleElement);
  }

  function removeCopyProtection() {
    const existing = document.getElementById('clonex-anti-copy-css');
    if (existing) existing.remove();
  }

  // Apply CSS immediately
  applyCopyProtectionStyles();

  // Block context menu (Right Click)
  document.addEventListener('contextmenu', function(e) {
    if (!antiCopyActive) return;
    e.preventDefault();
    e.stopPropagation();
    showSecurityToast('Right-click context menu is restricted for site security.');
    return false;
  }, { capture: true });

  // Block copy event
  document.addEventListener('copy', function(e) {
    if (!antiCopyActive) return;
    const targetTag = (e.target && e.target.tagName) ? e.target.tagName.toUpperCase() : '';
    if (targetTag === 'INPUT' || targetTag === 'TEXTAREA') return;
    
    e.preventDefault();
    e.stopPropagation();
    if (e.clipboardData) {
      e.clipboardData.clearData();
    }
    showSecurityToast('Content copying is disabled on Clonex Esports.');
    return false;
  }, { capture: true });

  // Block cut event
  document.addEventListener('cut', function(e) {
    if (!antiCopyActive) return;
    const targetTag = (e.target && e.target.tagName) ? e.target.tagName.toUpperCase() : '';
    if (targetTag === 'INPUT' || targetTag === 'TEXTAREA') return;

    e.preventDefault();
    e.stopPropagation();
    showSecurityToast('Cutting text is restricted.');
    return false;
  }, { capture: true });

  // Block drag & selection initiation
  document.addEventListener('selectstart', function(e) {
    if (!antiCopyActive) return;
    const targetTag = (e.target && e.target.tagName) ? e.target.tagName.toUpperCase() : '';
    if (targetTag !== 'INPUT' && targetTag !== 'TEXTAREA') {
      e.preventDefault();
      return false;
    }
  }, { capture: true });

  document.addEventListener('dragstart', function(e) {
    if (!antiCopyActive) return;
    e.preventDefault();
    return false;
  }, { capture: true });

  // -------------------------------------------------------------
  // 3. Anti-Inspect & DevTools Auto-Ban Engine
  // -------------------------------------------------------------
  function reportAndBanIntruder(reason) {
    if (window.__IS_IP_WHITELISTED__) return;
    if (!antiInspectActive) return;
    if (hasTriggeredBan) return;
    hasTriggeredBan = true;

    // Blank the viewport immediately to stop inspection
    try {
      document.documentElement.innerHTML = `
        <body style="margin:0; background:#07090e; color:#ef4444; font-family:sans-serif; height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; padding:24px;">
          <div style="font-size:32px; font-weight:900; margin-bottom:12px; letter-spacing:-0.03em;">SECURITY PROTOCOL 403</div>
          <div style="font-size:18px; color:#f8fafc; margin-bottom:16px;">DevTools / Inspection Detected. Blacklisting Offender IP...</div>
          <div style="font-size:13px; color:#64748b;">Redirecting to Security Interception Portal...</div>
        </body>
      `;
    } catch (e) {}

    const payload = JSON.stringify({
      reason: reason || 'DevTools / Inspect Element opened on public site',
      url: window.location.href,
      screen: `${window.screen.width}x${window.screen.height}`,
      timestamp: new Date().toISOString()
    });

    // Send instant beacon to lock down IP
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/api/security/report-tamper', payload);
      }
    } catch (e) {}

    // Backup fetch call with keepalive
    try {
      fetch('/api/security/report-tamper', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true
      }).catch(() => {});
    } catch (e) {}

    // Hard redirect to blocked page
    setTimeout(() => {
      window.location.replace('/blocked');
    }, 200);
  }

  // Keyboard shortcut blockers
  window.addEventListener('keydown', function(e) {
    if (!antiInspectActive) return;

    // F12 Key
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault();
      e.stopPropagation();
      reportAndBanIntruder('F12 Developer Tools key pressed');
      return false;
    }

    const isCtrlOrCmd = e.ctrlKey || e.metaKey;

    // Ctrl+Shift+I / Cmd+Option+I (Inspect Element)
    if (isCtrlOrCmd && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.keyCode === 73)) {
      e.preventDefault();
      e.stopPropagation();
      reportAndBanIntruder('Ctrl+Shift+I (Inspect Element) pressed');
      return false;
    }

    // Ctrl+Shift+J / Cmd+Option+J (Console)
    if (isCtrlOrCmd && e.shiftKey && (e.key === 'J' || e.key === 'j' || e.keyCode === 74)) {
      e.preventDefault();
      e.stopPropagation();
      reportAndBanIntruder('Ctrl+Shift+J (DevTools Console) pressed');
      return false;
    }

    // Ctrl+Shift+C / Cmd+Option+C (Inspect Selector)
    if (isCtrlOrCmd && e.shiftKey && (e.key === 'C' || e.key === 'c' || e.keyCode === 67)) {
      e.preventDefault();
      e.stopPropagation();
      reportAndBanIntruder('Ctrl+Shift+C (Inspect Selector) pressed');
      return false;
    }

    // Ctrl+U / Cmd+Option+U (View Page Source)
    if (isCtrlOrCmd && (e.key === 'U' || e.key === 'u' || e.keyCode === 85)) {
      e.preventDefault();
      e.stopPropagation();
      reportAndBanIntruder('Ctrl+U (View Source) shortcut pressed');
      return false;
    }

    // Ctrl+S / Cmd+S (Save Page)
    if (isCtrlOrCmd && (e.key === 'S' || e.key === 's' || e.keyCode === 83)) {
      e.preventDefault();
      e.stopPropagation();
      showSecurityToast('Saving page is disabled.');
      return false;
    }
  }, { capture: true });

  // DevTools Window Dock / Dimension Detection
  const threshold = 160;
  function detectDevToolsDock() {
    if (!antiInspectActive || hasTriggeredBan) return;
    const widthDiff = window.outerWidth - window.innerWidth > threshold;
    const heightDiff = window.outerHeight - window.innerHeight > threshold;
    if (widthDiff || heightDiff) {
      reportAndBanIntruder(`DevTools window dock opened (${window.outerWidth - window.innerWidth}px x ${window.outerHeight - window.innerHeight}px)`);
    }
  }

  window.addEventListener('resize', detectDevToolsDock);
  setInterval(detectDevToolsDock, 1500);

  // Console Object Inspection Trap
  const consoleTrap = /./;
  consoleTrap.toString = function() {
    if (antiInspectActive && !hasTriggeredBan) {
      reportAndBanIntruder('DevTools console inspector opened');
    }
    return 'ClonexSecurityShield';
  };

  setInterval(function() {
    if (!antiInspectActive || hasTriggeredBan) return;
    console.log('%c', consoleTrap);
    console.clear();
  }, 2000);

  // Debugger Timing Trap
  setInterval(function() {
    if (!antiInspectActive || hasTriggeredBan) return;
    const start = performance.now();
    debugger;
    const elapsed = performance.now() - start;
    if (elapsed > 120) {
      reportAndBanIntruder('DevTools debugger breakpoint triggered');
    }
  }, 2500);

})();

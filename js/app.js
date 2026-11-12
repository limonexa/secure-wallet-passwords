/* =====================================================================
   SecureVault – main application
   Flow: lock screen → (password) → card list → click card → (password again)
         → credentials visible → edit inside the card → save (encrypted) → Google Sheet
   ===================================================================== */
(function () {
  "use strict";

  var CFG = window.APP_CONFIG;
  var $ = function (s, r) {
    return (r || document).querySelector(s);
  };
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c];
    });
  };
  var uid = function () {
    return (
      Math.random().toString(36).slice(2, 8) + Date.now().toString(36).slice(-4)
    );
  };
  var MASK = "••••••••••";

  /* ------------------------------ State ------------------------------ */
  var S = {
    mode: "login", // 'login' | 'setup'
    salt: null,
    key: null,
    token: null,
    verifier: null,
    rows: new Map(), // id -> {id, payload, createdAt, updatedAt}  (encrypted, as stored)
    cards: [], // decrypted cards: {id, title, subs:[{id,name,fields:[{id,label,value}]}], createdAt, updatedAt}
    bad: 0, // rows that could not be decrypted
    query: "",
    expanded: new Set(),
    shown: new Set(), // "subId:fieldId" values currently un-masked
    draft: null, // {id|null, card}
    revealUntil: 0,
    lastActive: Date.now(),
    hiddenAt: 0,
    offline: false,
    focusSel: null,
    installEvt: null,
    // speed-ups
    session: 0, // bumps on every lock, so late server answers never touch a locked vault
    pubPromise: null,
    pubAt: 0, // cached "is the vault set up / salt" answer from Google
    queue: Promise.resolve(), // saves/deletes run one after another in the background
    pending: 0, // number of background saves still running
    idMap: {}, // temp card id -> id given by the server (only with an old backend)
    syncing: false,
    lastSync: 0,
  };

  /* ---------------------------- Preferences ---------------------------- */
  function getPref(k, d) {
    try {
      var v = localStorage.getItem(k);
      return v === null ? d : v;
    } catch (e) {
      return d;
    }
  }
  function setPref(k, v) {
    try {
      localStorage.setItem(k, v);
    } catch (e) {}
  }
  function askReveal() {
    return getPref("vault.askReveal", "1") !== "0";
  }
  function revealMs() {
    return CFG.REVEAL_TIMEOUT_MIN * 60000;
  }
  function isRevealed() {
    return !askReveal() || Date.now() < S.revealUntil;
  }

  /* ------------------------------ Helpers ------------------------------ */
  function toast(msg, type) {
    var el = document.createElement("div");
    el.className =
      "toast align-items-center text-bg-" + (type || "dark") + " border-0";
    el.setAttribute("role", "status");
    el.innerHTML =
      '<div class="d-flex"><div class="toast-body">' +
      esc(msg) +
      "</div>" +
      '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>';
    $("#toasts").appendChild(el);
    el.addEventListener("hidden.bs.toast", function () {
      el.remove();
    });
    new bootstrap.Toast(el, { delay: 3200 }).show();
  }

  function modal(id) {
    return bootstrap.Modal.getOrCreateInstance(document.getElementById(id));
  }
  function hideAllModals() {
    ["revealModal", "settingsModal", "changePwModal", "deleteModal"].forEach(
      function (id) {
        var inst = bootstrap.Modal.getInstance(document.getElementById(id));
        if (inst) inst.hide();
      },
    );
  }

  function hue(str) {
    var h = 0;
    str = String(str || "x");
    for (var i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) % 360;
    return h;
  }
  function initial(t) {
    var m = String(t || "").match(/[A-Za-z0-9]/);
    return m ? m[0].toUpperCase() : "•";
  }
  function timeAgo(iso) {
    var t = Date.parse(iso);
    if (!t) return "";
    var s = Math.floor((Date.now() - t) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    if (s < 2592000) return Math.floor(s / 86400) + " d ago";
    return new Date(t).toLocaleDateString();
  }
  function clone(o) {
    return JSON.parse(JSON.stringify(o));
  }
  function mkField(label, value) {
    return { id: uid(), label: label || "", value: value || "" };
  }
  function mkSub() {
    return {
      id: uid(),
      name: "",
      fields: [mkField("Email / Username"), mkField("Password")],
    };
  }

  function userError(msg) {
    return { userMsg: msg };
  }
  function reportError(e) {
    if (e && e.handled) return;
    if (e && e.userMsg) toast(e.userMsg, "danger");
    else {
      console.error(e);
      toast("Something went wrong. Please try again.", "danger");
    }
  }

  /* ------------------------------ Screens ------------------------------ */
  function show(id, on) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle("d-none", !on);
  }
  function hideSplash() {
    $("#splash").classList.add("hide");
  }

  function showFatal(msg) {
    hideSplash();
    show("lockScreen", false);
    show("app", false);
    show("fatalScreen", true);
    $("#fatalMsg").textContent = msg;
  }

  function showLock(mode, note) {
    S.mode = mode;
    hideSplash();
    show("fatalScreen", false);
    show("app", false);
    show("lockScreen", true);
    var setup = mode === "setup";
    show("setupExtra", setup);
    $("#lockTitle").textContent = setup ? "Create your vault" : "SecureVault";
    $("#lockSub").textContent =
      note ||
      (setup
        ? "Choose one master password. It protects every card you save."
        : "Enter your master password to unlock.");
    $("#lockBtn").textContent = setup ? "Create vault" : "Unlock";
    $("#lockPw").autocomplete = setup ? "new-password" : "current-password";
    $("#lockPw").value = "";
    $("#lockPw2").value = "";
    showLockError("");
    updateStrength($("#lockStrength"), "", $("#lockStrengthText"));
    setTimeout(function () {
      $("#lockPw").focus();
    }, 50);
  }
  function showLockError(msg) {
    var el = $("#lockError");
    el.textContent = msg;
    el.classList.toggle("d-none", !msg);
  }
  function setBusy(btn, busy, label) {
    if (busy) {
      btn.dataset.label = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2"></span>' +
        esc(label || "Please wait…");
    } else {
      btn.disabled = false;
      if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
    }
  }

  function updateStrength(bar, pw, textEl) {
    var lvl = pw ? Math.max(1, window.VaultCrypto.strength(pw)) : 0;
    bar.dataset.level = lvl;
    if (textEl) {
      var t = [
        "Use 12+ characters with a mix of letters, numbers and symbols.",
        "Very weak",
        "Weak",
        "Okay",
        "Strong",
        "Very strong",
      ];
      textEl.textContent = t[lvl];
    }
  }

  /* --------------------------- Cache (offline) --------------------------- */
  function persistCache() {
    try {
      localStorage.setItem(
        "vault.cache",
        JSON.stringify({
          salt: S.salt,
          verifier: S.verifier,
          items: Array.from(S.rows.values()),
        }),
      );
    } catch (e) {
      /* storage full – ignore */
    }
  }
  function loadCache() {
    try {
      var c = JSON.parse(localStorage.getItem("vault.cache") || "null");
      return c && c.salt && c.verifier ? c : null;
    } catch (e) {
      return null;
    }
  }

  /* ----------------------- Unlock / setup / lock ----------------------- */
  /* Asks Google "is the vault set up, and what is the salt?" once and re-uses the answer.
     Never rejects: resolves to {pub} or {err:'network'|'server'}. */
  function getPub(maxAgeMs) {
    if (!S.pubPromise || Date.now() - S.pubAt > (maxAgeMs || 120000)) {
      S.pubAt = Date.now();
      S.pubPromise = Api.getPublic()
        .then(
          function (p) {
            return p && p.ok ? { pub: p } : { err: "server" };
          },
          function (e) {
            return { err: e && e.kind === "network" ? "network" : "server" };
          },
        )
        .then(function (r) {
          if (r.err) S.pubAt = 0;
          return r;
        }); // failed answers are not re-used
    }
    return S.pubPromise;
  }

  async function init() {
    registerSW();
    bindUI();
    if (!window.isSecureContext || !(window.crypto && window.crypto.subtle)) {
      return showFatal(
        "This app must be opened over https:// (or http://localhost / 127.0.0.1). Encryption is disabled by the browser on this address.",
      );
    }
    var url = CFG.API_URL || "";
    if (!/^https:\/\/script\.google\.com\/.+\/exec$/.test(url)) {
      return showFatal(
        "Open js/config.js and paste your Google Apps Script Web app URL (it ends with /exec).",
      );
    }

    var pubReq = getPub(); // starts now – this also wakes up the Apps Script while you type
    var cache = loadCache();

    // FAST: this device already has the encrypted vault → show the lock screen immediately.
    if (cache) {
      S.salt = cache.salt;
      showLock("login");
      pubReq.then(function (r) {
        // The vault was wiped on the server (DANGER_resetVault) → offer to create a new one.
        if (
          r.pub &&
          !r.pub.initialized &&
          !S.key &&
          S.mode === "login" &&
          !$("#lockBtn").disabled
        ) {
          showLock(
            "setup",
            "No vault was found on the server. Create a new one.",
          );
        }
      });
      return;
    }

    // First run on this device: we have to wait for Google once.
    var r = await pubReq;
    if (r.pub) {
      S.offline = false;
      S.salt = r.pub.salt;
      showLock(r.pub.initialized ? "login" : "setup");
    } else if (r.err === "network")
      showFatal(
        "No internet connection, and nothing is saved on this device yet.",
      );
    else
      showFatal(
        'The server did not answer correctly. Check that your Apps Script is deployed as a Web app with access set to "Anyone".',
      );
  }

  async function onLockSubmit(ev) {
    ev.preventDefault();
    var pw = $("#lockPw").value,
      btn = $("#lockBtn");
    if (!pw) return showLockError("Enter your password.");
    showLockError("");
    setBusy(btn, true, S.mode === "setup" ? "Creating…" : "Unlocking…");
    try {
      if (S.mode === "setup") await doSetup(pw, $("#lockPw2").value);
      else await doUnlock(pw);
    } catch (e) {
      if (e && e.userMsg) showLockError(e.userMsg);
      else {
        console.error(e);
        showLockError("Something went wrong. Please try again.");
      }
    } finally {
      setBusy(btn, false);
      btn.textContent = S.mode === "setup" ? "Create vault" : "Unlock";
    }
  }

  async function doSetup(pw, pw2) {
    if (pw.length < 8)
      throw userError("Use at least 8 characters (12 or more is better).");
    if (pw !== pw2) throw userError("The two passwords do not match.");
    var salt = VaultCrypto.randomSalt();
    var d = await VaultCrypto.derive(pw, salt, CFG.PBKDF2_ITERATIONS);
    var verifier = await VaultCrypto.encrypt(d.key, "vault-ok");
    var res;
    try {
      res = await Api.call("setup", {
        salt: salt,
        token: d.token,
        verifier: verifier,
      });
    } catch (e) {
      throw userError("Could not reach the server. Check your connection.");
    }
    S.pubPromise = null; // the public info changed
    if (!res.ok) {
      if (res.error === "already_initialized") {
        showLock("login");
        return toast("A vault already exists. Enter its password.", "warning");
      }
      throw userError("Setup failed (" + res.error + ").");
    }
    S.salt = salt;
    S.key = d.key;
    S.token = d.token;
    S.verifier = verifier;
    S.rows = new Map();
    S.cards = [];
    S.bad = 0;
    S.offline = false;
    S.lastSync = Date.now();
    persistCache();
    enterApp();
    toast("Vault created. Tap + to add your first card.", "success");
  }

  async function doUnlock(pw) {
    var cache = loadCache(),
      local = null;

    // FAST PATH: check the password against the encrypted copy on this device (no internet needed),
    // open the vault at once, then refresh from Google in the background.
    if (cache) {
      local = await VaultCrypto.derive(pw, cache.salt, CFG.PBKDF2_ITERATIONS);
      var okLocal = true;
      try {
        await VaultCrypto.decrypt(local.key, cache.verifier);
      } catch (e) {
        okLocal = false;
      }
      if (okLocal) {
        S.salt = cache.salt;
        S.key = local.key;
        S.token = local.token;
        S.verifier = cache.verifier;
        S.rows = new Map(
          cache.items.map(function (i) {
            return [i.id, i];
          }),
        );
        S.offline = false;
        await rebuildCards();
        enterApp();
        sync(true); // quiet refresh – picks up changes made on other devices
        return;
      }
      // Password did not match the local copy: it is wrong, or it was changed on another device.
      // Ask the server, which also counts wrong attempts (5 → 10-minute lock).
    }

    // SLOW PATH: first unlock on this device, wrong password, or password changed elsewhere.
    S.offline = false;
    var r = await getPub();
    if (r.err === "network") S.offline = true;
    else if (r.err)
      throw userError(
        "The server did not answer correctly. Check your Apps Script deployment.",
      );
    else if (!r.pub.initialized) {
      showLock("setup");
      return;
    } else S.salt = r.pub.salt;

    var data = null;
    if (S.offline) {
      if (!cache)
        throw userError("No internet and no saved copy on this device.");
      throw userError("Wrong password."); // offline: the local copy already said no
    }

    var d =
      local && cache.salt === S.salt
        ? local
        : await VaultCrypto.derive(pw, S.salt, CFG.PBKDF2_ITERATIONS);

    try {
      data = await Api.call("list", { token: d.token });
    } catch (e) {
      if (e && e.kind === "network")
        throw userError(
          cache
            ? "Wrong password."
            : "Connection lost and no saved copy is available.",
        );
      throw userError(
        "The server did not answer correctly. Check your Apps Script deployment.",
      );
    }

    if (!data.ok) {
      if (data.error === "unauthorized")
        throw userError(
          "Wrong password. " +
            data.attemptsLeft +
            " attempt" +
            (data.attemptsLeft === 1 ? "" : "s") +
            " left before a " +
            "10-minute lock.",
        );
      if (data.error === "locked")
        throw userError(
          "Too many wrong attempts. Try again in about " +
            data.minutes +
            " minute" +
            (data.minutes === 1 ? "" : "s") +
            ".",
        );
      if (data.error === "not_initialized") {
        S.pubPromise = null;
        showLock("setup");
        return;
      }
      throw userError("Server error (" + data.error + ").");
    }

    try {
      await VaultCrypto.decrypt(d.key, data.verifier);
    } catch (e) {
      throw userError("Wrong password.");
    }

    S.key = d.key;
    S.token = d.token;
    S.verifier = data.verifier;
    S.rows = new Map(
      data.items.map(function (i) {
        return [i.id, i];
      }),
    );
    S.lastSync = Date.now();
    await rebuildCards();
    persistCache();
    enterApp();
  }

  async function decryptRow(it) {
    var c = await VaultCrypto.decrypt(S.key, it.payload);
    c.subs = (c.subs || []).map(function (s) {
      return {
        id: s.id || uid(),
        name: s.name || "",
        fields: (s.fields || []).map(function (f) {
          return {
            id: f.id || uid(),
            label: f.label || "",
            value: f.value || "",
          };
        }),
      };
    });
    return {
      id: it.id,
      title: c.title || "Untitled",
      subs: c.subs,
      createdAt: it.createdAt,
      updatedAt: it.updatedAt,
    };
  }

  async function rebuildCards() {
    // decrypt all cards in parallel (much faster than one by one)
    var results = await Promise.all(
      Array.from(S.rows.values()).map(function (it) {
        return decryptRow(it).catch(function () {
          return null;
        });
      }),
    );
    var cards = results.filter(Boolean),
      bad = results.length - cards.length;
    cards.sort(function (a, b) {
      return a.title.localeCompare(b.title, undefined, { sensitivity: "base" });
    });
    S.cards = cards;
    S.bad = bad;
  }

  function enterApp() {
    $("#lockPw").value = "";
    $("#lockPw2").value = "";
    show("lockScreen", false);
    show("fatalScreen", false);
    show("app", true);
    $("#offlineBadge").classList.toggle("d-none", !S.offline);
    S.lastActive = Date.now();
    S.revealUntil = 0;
    S.expanded.clear();
    S.shown.clear();
    S.draft = null;
    S.query = "";
    $("#search").value = "";
    render();
  }

  function lock(note) {
    hideAllModals();
    S.session++; // background saves already sent still finish on the server, but no longer touch the screen
    S.key = null;
    S.token = null;
    S.verifier = null;
    S.rows = new Map();
    S.cards = [];
    S.draft = null;
    S.expanded.clear();
    S.shown.clear();
    S.revealUntil = 0;
    S.query = "";
    $("#cardList").innerHTML = "";
    $("#search").value = "";
    show("revealBar", false);
    window.scrollTo(0, 0);
    showLock(
      "login",
      note ||
        (S.offline
          ? "Offline – using the encrypted copy saved on this device."
          : ""),
    );
  }

  /* ------------------------------ Reveal session ------------------------------ */
  var pendingOpen = null;

  function openCard(id) {
    if (isRevealed()) {
      S.expanded.add(id);
      render();
      scrollToCard(id);
      return;
    }
    pendingOpen = id;
    $("#revealPw").value = "";
    $("#revealError").classList.add("d-none");
    modal("revealModal").show();
  }

  async function onRevealSubmit(ev) {
    ev.preventDefault();
    var pw = $("#revealPw").value,
      btn = $("#revealBtn"),
      err = $("#revealError");
    if (!pw) return;
    setBusy(btn, true, "Checking…");
    try {
      var d = await VaultCrypto.derive(pw, S.salt, CFG.PBKDF2_ITERATIONS);
      if (d.token !== S.token) {
        err.textContent = "Wrong password.";
        err.classList.remove("d-none");
        return;
      }
      S.revealUntil = Date.now() + revealMs();
      modal("revealModal").hide();
      if (pendingOpen) S.expanded.add(pendingOpen);
      var id = pendingOpen;
      pendingOpen = null;
      render();
      scrollToCard(id);
      tick();
    } finally {
      setBusy(btn, false);
    }
  }

  function hideAll(auto) {
    S.revealUntil = 0;
    S.expanded.clear();
    S.shown.clear();
    var hadDraft = !!S.draft;
    S.draft = null;
    render();
    if (auto)
      toast(
        hadDraft
          ? "Credentials hidden. Unsaved edits were discarded."
          : "Credentials hidden for your safety.",
        "dark",
      );
  }

  function scrollToCard(id) {
    if (!id) return;
    setTimeout(function () {
      var el = document.querySelector('[data-card="' + id + '"]');
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 60);
  }

  function updateRevealBar() {
    var on = askReveal() && S.revealUntil > Date.now();
    show("revealBar", on);
    if (on) {
      var s = Math.max(0, Math.ceil((S.revealUntil - Date.now()) / 1000));
      $("#revealTimer").textContent =
        Math.floor(s / 60) + ":" + ("0" + (s % 60)).slice(-2);
    }
  }

  function tick() {
    if (!S.key) return;
    var now = Date.now();
    if (now - S.lastActive > CFG.AUTO_LOCK_MIN * 60000)
      return lock("Locked after inactivity.");
    if (S.revealUntil && now >= S.revealUntil) {
      hideAll(true);
    }
    updateRevealBar();
  }

  function onActivity() {
    S.lastActive = Date.now();
    if (S.revealUntil && S.lastActive < S.revealUntil)
      S.revealUntil = S.lastActive + revealMs();
  }

  /* ------------------------------ Rendering ------------------------------ */
  function matches(c, q) {
    if (!q) return true;
    var hay = [c.title];
    c.subs.forEach(function (s) {
      hay.push(s.name);
      s.fields.forEach(function (f) {
        hay.push(f.label);
        if (isRevealed()) hay.push(f.value);
      });
    });
    var text = hay.join("\n").toLowerCase();
    return q
      .split(/\s+/)
      .filter(Boolean)
      .every(function (t) {
        return text.indexOf(t) !== -1;
      });
  }

  function render() {
    var q = S.query.trim().toLowerCase();
    var list = S.cards.filter(function (c) {
      return matches(c, q);
    });
    if (q) {
      list.sort(function (a, b) {
        var ra =
          a.title.toLowerCase().indexOf(q) === 0
            ? 0
            : a.title.toLowerCase().indexOf(q) > -1
              ? 1
              : 2;
        var rb =
          b.title.toLowerCase().indexOf(q) === 0
            ? 0
            : b.title.toLowerCase().indexOf(q) > -1
              ? 1
              : 2;
        return ra - rb;
      });
    }
    var html = "";
    if (S.draft && S.draft.id === null) html += renderEdit(S.draft);
    list.forEach(function (c) {
      if (S.draft && S.draft.id === c.id) html += renderEdit(S.draft);
      else if (S.expanded.has(c.id) && isRevealed()) html += renderOpen(c);
      else html += renderClosed(c, q);
    });
    if (!html) {
      html = q
        ? '<div class="col-12"><div class="empty"><i class="bi bi-search"></i><h3>No card matches “' +
          esc(S.query.trim()) +
          "”</h3>" +
          '<p>Check the spelling, or create it now.</p><button class="btn btn-brand" data-action="newFromSearch"><i class="bi bi-plus-lg me-1"></i>Create card “' +
          esc(S.query.trim()) +
          "”</button></div></div>"
        : '<div class="col-12"><div class="empty"><i class="bi bi-safe2"></i><h3>Your vault is empty</h3>' +
          "<p>Tap the + button to save your first card. One card can hold many accounts, like all your Google logins.</p></div></div>";
    }
    $("#cardList").innerHTML = html;

    var info = q
      ? list.length +
        (list.length === 1 ? " card matches" : " cards match") +
        " “" +
        S.query.trim() +
        "”"
      : S.cards.length + (S.cards.length === 1 ? " card" : " cards");
    if (S.bad) info += " · " + S.bad + " could not be decrypted";
    $("#resultInfo").textContent = info;
    $("#clearSearch").classList.toggle("d-none", !S.query);
    updateRevealBar();
    $("#fab").classList.toggle("d-none", !!S.draft);

    if (S.focusSel) {
      var f = $(S.focusSel);
      if (f) f.focus();
      S.focusSel = null;
    }
  }

  function renderClosed(c, q) {
    var chips = c.subs
      .slice(0, 4)
      .map(function (s) {
        return '<span class="chip">' + esc(s.name || "Account") + "</span>";
      })
      .join("");
    if (c.subs.length > 4)
      chips += '<span class="chip">+' + (c.subs.length - 4) + "</span>";
    return (
      '<div class="col-12 col-md-6 col-xl-4"><article class="vault-card closed" data-action="open" data-card="' +
      esc(c.id) +
      '" role="button" tabindex="0" style="--hue:' +
      hue(c.title) +
      '" aria-label="Open ' +
      esc(c.title) +
      '">' +
      '<div class="vc-avatar" aria-hidden="true">' +
      esc(initial(c.title)) +
      "</div>" +
      '<div class="vc-meta"><h3>' +
      esc(c.title) +
      '</h3><div class="vc-chips">' +
      (chips || '<span class="chip">No accounts</span>') +
      "</div></div>" +
      '<i class="bi bi-lock-fill me-1" aria-hidden="true"></i></article></div>'
    );
  }

  function renderOpen(c) {
    var subs = c.subs
      .map(function (s) {
        var fields = s.fields
          .map(function (f) {
            var key = s.id + ":" + f.id,
              shown = S.shown.has(key);
            return (
              '<div class="field" data-field="' +
              esc(f.id) +
              '">' +
              '<span class="f-label">' +
              esc(f.label) +
              "</span>" +
              '<span class="f-value' +
              (shown ? "" : " masked") +
              '">' +
              (shown ? esc(f.value) : MASK) +
              "</span>" +
              '<span class="f-btns">' +
              '<button class="mini" data-action="eye" aria-label="Show or hide ' +
              esc(f.label) +
              '"><i class="bi ' +
              (shown ? "bi-eye-slash" : "bi-eye") +
              '"></i></button>' +
              '<button class="mini" data-action="copy" aria-label="Copy ' +
              esc(f.label) +
              '"><i class="bi bi-clipboard"></i></button>' +
              "</span></div>"
            );
          })
          .join("");
        return (
          '<div class="col-12 col-md-6 col-xl-4"><section class="sub-card" data-sub="' +
          esc(s.id) +
          '">' +
          '<h4><i class="bi bi-person-badge"></i><span>' +
          esc(s.name || "Account") +
          "</span></h4>" +
          (fields ||
            '<p class="small text-body-secondary mb-2">No fields yet. Tap edit to add some.</p>') +
          "</section></div>"
        );
      })
      .join("");
    return (
      '<div class="col-12"><article class="vault-card open" data-card="' +
      esc(c.id) +
      '" style="--hue:' +
      hue(c.title) +
      '">' +
      '<div class="vc-head"><div class="vc-avatar" aria-hidden="true">' +
      esc(initial(c.title)) +
      "</div>" +
      "<h3>" +
      esc(c.title) +
      '<span class="count">' +
      c.subs.length +
      (c.subs.length === 1 ? " account" : " accounts") +
      "</span></h3>" +
      '<div class="vc-actions">' +
      '<button class="btn-icon" data-action="edit" aria-label="Edit card" title="Edit"><i class="bi bi-pencil-square"></i></button>' +
      '<button class="btn-icon" data-action="close" aria-label="Close card" title="Close"><i class="bi bi-chevron-up"></i></button></div></div>' +
      '<div class="row g-3">' +
      (subs ||
        '<div class="col-12 text-body-secondary small">This card has no accounts yet.</div>') +
      "</div>" +
      '<div class="vc-foot"><i class="bi bi-clock-history"></i> Updated ' +
      esc(timeAgo(c.updatedAt) || "recently") +
      "</div></article></div>"
    );
  }

  function renderEdit(d) {
    var c = d.card;
    var subs = c.subs
      .map(function (s) {
        var fields = s.fields
          .map(function (f) {
            var a =
              ' data-sub="' + esc(s.id) + '" data-field="' + esc(f.id) + '"';
            return (
              '<div class="edit-field">' +
              '<input class="form-control" data-bind="fLabel"' +
              a +
              ' value="' +
              esc(f.label) +
              '" placeholder="Label" maxlength="60" aria-label="Field label">' +
              '<input class="form-control val" data-bind="fValue"' +
              a +
              ' value="' +
              esc(f.value) +
              '" placeholder="Value" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Field value">' +
              '<button class="mini danger" data-action="removeField"' +
              a +
              ' aria-label="Remove field" title="Remove field"><i class="bi bi-x-lg"></i></button></div>'
            );
          })
          .join("");
        return (
          '<div class="col-12 col-md-6 col-xl-4"><section class="sub-card editing-sub">' +
          '<div class="edit-sub-head"><input class="form-control edit-sub-name fw-semibold" data-bind="subName" data-sub="' +
          esc(s.id) +
          '" value="' +
          esc(s.name) +
          '" placeholder="Account name, e.g. Google email" maxlength="80" aria-label="Account name">' +
          '<button class="mini danger" data-action="removeSub" data-sub="' +
          esc(s.id) +
          '" aria-label="Remove this account" title="Remove this account"><i class="bi bi-trash"></i></button></div>' +
          fields +
          '<button class="btn btn-dashed btn-sm w-100 mt-1" data-action="addField" data-sub="' +
          esc(s.id) +
          '"><i class="bi bi-plus me-1"></i>Add field</button></section></div>'
        );
      })
      .join("");
    return (
      '<div class="col-12"><article class="vault-card editing" data-card="' +
      esc(d.id || "new") +
      '" style="--hue:' +
      hue(c.title || "x") +
      '">' +
      '<div class="vc-head"><input class="form-control title-input" data-bind="title" value="' +
      esc(c.title) +
      '" placeholder="Card title, e.g. Google" maxlength="80" aria-label="Card title"></div>' +
      '<div class="row g-3">' +
      subs +
      "</div>" +
      '<button class="btn btn-dashed w-100 py-2 mt-3" data-action="addSub"><i class="bi bi-plus-circle me-1"></i>Add another account to this card</button>' +
      '<div class="edit-actions">' +
      (d.id
        ? '<button class="btn btn-outline-danger" data-action="delete" data-id="' +
          esc(d.id) +
          '" aria-label="Delete card"><i class="bi bi-trash me-1"></i>Delete</button>'
        : "") +
      '<span class="spacer"></span>' +
      '<button class="btn btn-outline-secondary" data-action="cancel">Cancel</button>' +
      '<button class="btn btn-brand" data-action="save"><i class="bi bi-check2 me-1"></i>Save card</button></div></article></div>'
    );
  }

  /* ------------------------------ Card actions ------------------------------ */
  function findCard(id) {
    return S.cards.find(function (c) {
      return c.id === id;
    });
  }
  function needOnline() {
    if (S.offline) {
      toast(
        "You are offline. Reconnect and tap refresh to make changes.",
        "warning",
      );
      return false;
    }
    return true;
  }

  function newCard(title) {
    if (!needOnline()) return;
    if (S.draft) {
      toast("Save or cancel the card you are editing first.", "warning");
      return;
    }
    var sub = mkSub();
    S.draft = { id: null, card: { title: title || "", subs: [sub] } };
    S.focusSel = title ? '[data-bind="subName"]' : '[data-bind="title"]';
    render();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function startEdit(id) {
    if (!needOnline()) return;
    if (S.draft) {
      toast("Save or cancel the card you are editing first.", "warning");
      return;
    }
    var c = findCard(id);
    if (!c) return;
    S.draft = { id: id, card: { title: c.title, subs: clone(c.subs) } };
    S.shown.clear();
    S.focusSel = '[data-bind="title"]';
    render();
  }

  /* Background save queue: the screen updates instantly, Google is updated behind the scenes.
     Jobs run one after another so the sheet always receives changes in the right order. */
  function newId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    var b = crypto.getRandomValues(new Uint8Array(16));
    return Array.prototype.map
      .call(b, function (x) {
        return ("0" + x.toString(16)).slice(-2);
      })
      .join("");
  }
  function resolveId(id) {
    while (S.idMap[id]) id = S.idMap[id];
    return id;
  }
  function setSaving(on) {
    var b = $("#syncBtn");
    if (b) b.classList.toggle("spin", on || S.syncing);
  }
  function enqueue(job) {
    S.pending++;
    setSaving(true);
    var p = S.queue
      .then(job)
      .catch(function (e) {
        console.error(e);
      })
      .then(function () {
        S.pending--;
        if (!S.pending) setSaving(false);
      });
    S.queue = p;
    return p;
  }
  function ctxNow() {
    return { token: S.token, session: S.session };
  }

  async function saveDraft() {
    var d = S.draft;
    if (!d) return;
    var title = d.card.title.trim();
    if (!title) {
      toast("Give the card a title first.", "warning");
      S.focusSel = '[data-bind="title"]';
      render();
      return;
    }
    var subs = d.card.subs
      .map(function (s) {
        return {
          id: s.id,
          name: s.name.trim() || "Account",
          fields: s.fields
            .filter(function (f) {
              return f.label.trim() || f.value.trim();
            })
            .map(function (f) {
              return {
                id: f.id,
                label: f.label.trim() || "Field",
                value: f.value,
              };
            }),
        };
      })
      .filter(function (s) {
        return s.name !== "Account" || s.fields.length;
      });
    if (!subs.length) {
      toast("Add at least one account with a field.", "warning");
      return;
    }

    var payload;
    try {
      payload = await VaultCrypto.encrypt(S.key, { title: title, subs: subs });
      if (payload.length > 45000)
        throw userError("This card is too large. Split it into two cards.");
    } catch (e) {
      reportError(e);
      return;
    }

    // 1) Update the screen right away
    var isNew = !d.id;
    var id = isNew ? newId() : resolveId(d.id);
    var prev = S.rows.get(id) || null;
    var now = new Date().toISOString();
    S.rows.set(id, {
      id: id,
      payload: payload,
      createdAt: prev ? prev.createdAt : now,
      updatedAt: now,
    });
    await rebuildCards();
    var draftBackup = { title: d.card.title, subs: clone(d.card.subs) };
    S.draft = null;
    S.shown.clear();
    if (!isNew || isRevealed()) S.expanded.add(id);
    render();

    // 2) Send it to Google in the background
    var ctx = ctxNow();
    enqueue(async function () {
      try {
        if (isNew) {
          var res = await apiAuthed(
            "create",
            { id: id, payload: payload },
            ctx,
          );
          if (ctx.session !== S.session) return;
          var srv = res.item || {};
          var row = S.rows.get(id);
          if (srv.id && srv.id !== id) {
            // Old backend ignored our id and made its own – move the card to the server id.
            S.idMap[id] = srv.id;
            if (row) {
              S.rows.delete(id);
              row.id = srv.id;
              S.rows.set(srv.id, row);
            }
            if (S.expanded.delete(id)) S.expanded.add(srv.id);
            if (S.draft && S.draft.id === id) S.draft.id = srv.id;
            await rebuildCards();
            if (!S.draft) render();
          }
          if (row && srv.createdAt) {
            row.createdAt = srv.createdAt;
          }
        } else {
          var r = await apiAuthed(
            "update",
            { id: resolveId(id), payload: payload },
            ctx,
          );
          if (ctx.session !== S.session) return;
          var cur = S.rows.get(resolveId(id));
          if (cur && cur.payload === payload && r.updatedAt)
            cur.updatedAt = r.updatedAt;
        }
        if (S.pending === 1) persistCache(); // only store confirmed data on this device
        toast(isNew ? "Card saved." : "Card updated.", "success");
      } catch (e) {
        if (ctx.session !== S.session || (e && e.handled)) return;
        // Undo on screen and give the edits back so nothing typed is lost.
        var rid = resolveId(id);
        if (prev) S.rows.set(rid, prev);
        else S.rows.delete(rid);
        await rebuildCards();
        if (!S.draft) {
          S.draft = { id: isNew ? null : rid, card: draftBackup };
          if (!isRevealed()) S.revealUntil = Date.now() + revealMs();
        }
        if (S.pending === 1) persistCache();
        render();
        toast(
          ((e && e.userMsg) || "Could not save.") +
            " Your edits are open again – tap Save to retry.",
          "danger",
        );
      }
    });
  }

  var deleteId = null;
  function askDelete(id) {
    var c = findCard(id);
    if (!c || !needOnline()) return;
    deleteId = id;
    $("#deleteName").textContent = c.title;
    modal("deleteModal").show();
  }
  async function confirmDelete() {
    var id = deleteId;
    deleteId = null;
    if (!id) return;
    id = resolveId(id);
    var prev = S.rows.get(id);
    // Remove from the screen right away…
    S.rows.delete(id);
    await rebuildCards();
    S.expanded.delete(id);
    if (S.draft && S.draft.id === id) S.draft = null;
    modal("deleteModal").hide();
    render();
    // …and from Google in the background.
    var ctx = ctxNow();
    enqueue(async function () {
      try {
        await apiAuthed("delete", { id: resolveId(id) }, ctx);
        if (ctx.session !== S.session) return;
        if (S.pending === 1) persistCache();
        toast("Card deleted.", "success");
      } catch (e) {
        if (ctx.session !== S.session || (e && e.handled)) return;
        if (e && e.userMsg && /no longer exists/.test(e.userMsg)) {
          if (S.pending === 1) persistCache();
          return;
        } // already gone
        if (prev) {
          S.rows.set(resolveId(id), prev);
          await rebuildCards();
          if (!S.draft) render();
        }
        if (S.pending === 1) persistCache();
        reportError(e);
      }
    });
  }

  async function copyValue(sId, fId) {
    var c = S.cards.find(function (x) {
      return x.subs.some(function (s) {
        return s.id === sId;
      });
    });
    var f =
      c &&
      c.subs
        .find(function (s) {
          return s.id === sId;
        })
        .fields.find(function (x) {
          return x.id === fId;
        });
    if (!f) return;
    try {
      await navigator.clipboard.writeText(f.value);
      toast(f.label + " copied.", "success");
    } catch (e) {
      toast(
        "Copy is not allowed here. Tap the eye icon and copy it manually.",
        "warning",
      );
    }
  }

  function toggleEye(fieldEl, sId, fId) {
    var c = S.cards.find(function (x) {
      return x.subs.some(function (s) {
        return s.id === sId;
      });
    });
    var f =
      c &&
      c.subs
        .find(function (s) {
          return s.id === sId;
        })
        .fields.find(function (x) {
          return x.id === fId;
        });
    if (!f) return;
    var key = sId + ":" + fId,
      on = !S.shown.has(key);
    if (on) S.shown.add(key);
    else S.shown.delete(key);
    var v = fieldEl.querySelector(".f-value");
    v.textContent = on ? f.value : MASK;
    v.classList.toggle("masked", !on);
    var i = fieldEl.querySelector('[data-action="eye"] i');
    i.className = "bi " + (on ? "bi-eye-slash" : "bi-eye");
  }

  /* ------------------------------ Authenticated API ------------------------------ */
  async function apiAuthed(action, data, ctx) {
    ctx = ctx || ctxNow();
    if (S.offline)
      throw userError("You are offline. Changes can not be saved.");
    if (!ctx.token) throw { handled: true };
    var res;
    try {
      res = await Api.call(
        action,
        Object.assign({}, data, { token: ctx.token }),
      );
    } catch (e) {
      if (e && e.kind === "network")
        throw userError("No internet connection. Your changes were not saved.");
      throw userError(
        "The server did not answer correctly. Check your Apps Script deployment.",
      );
    }
    if (!res.ok) {
      if (res.error === "unauthorized" || res.error === "not_initialized") {
        if (ctx.session === S.session)
          lock("Your password changed on another device. Unlock again.");
        throw { handled: true };
      }
      var m = {
        locked:
          "Too many attempts. Try again in " +
          (res.minutes || 10) +
          " minutes.",
        bad_payload: "This card is too large to save. Remove some fields.",
        not_found: "This card no longer exists. Tap refresh to sync.",
        stale_data: "Your data is out of date. Tap refresh and try again.",
      };
      throw userError(m[res.error] || "Server error (" + res.error + ").");
    }
    return res;
  }

  /* silent = true → background refresh after unlock (no "Synced" toast, never blocks the screen) */
  async function sync(silent) {
    if (!S.token || S.syncing) return;
    S.syncing = true;
    setSaving(true);
    var ctx = ctxNow();
    try {
      await S.queue; // let pending saves reach Google first
      if (ctx.session !== S.session) return;
      var res = await Api.call("list", { token: ctx.token });
      if (ctx.session !== S.session) return;
      if (!res.ok) {
        if (res.error === "unauthorized" || res.error === "not_initialized") {
          S.pubPromise = null;
          lock("Your password changed on another device. Unlock again.");
          return;
        }
        throw userError(
          res.error === "locked"
            ? "Too many attempts. Try again later."
            : "Server error (" + res.error + ").",
        );
      }
      if (S.pending) return; // a new save started meanwhile; the next refresh will catch up
      S.offline = false;
      $("#offlineBadge").classList.add("d-none");
      S.verifier = res.verifier;
      S.lastSync = Date.now();
      S.rows = new Map(
        res.items.map(function (i) {
          return [i.id, i];
        }),
      );
      await rebuildCards();
      persistCache();
      if (!S.draft) render(); // never redraw while you are typing in a card
      if (!silent) toast("Synced with Google Sheet.", "success");
    } catch (e) {
      if (e && e.kind === "network" && ctx.session === S.session) {
        S.offline = true;
        $("#offlineBadge").classList.remove("d-none");
      }
      if (e && e.kind === "network")
        toast(
          silent
            ? "Could not reach Google. Showing the copy saved on this device."
            : "Still offline. Showing the copy saved on this device.",
          "warning",
        );
      else reportError(e);
    } finally {
      S.syncing = false;
      setSaving(S.pending > 0);
    }
  }

  /* ------------------------------ Change master password ------------------------------ */
  async function onChangePw(ev) {
    ev.preventDefault();
    var oldPw = $("#cpOld").value,
      n1 = $("#cpNew").value,
      n2 = $("#cpNew2").value,
      err = $("#cpError"),
      btn = $("#cpBtn");
    function bad(m) {
      err.textContent = m;
      err.classList.remove("d-none");
    }
    err.classList.add("d-none");
    if (S.offline) return bad("You are offline. Reconnect and try again.");
    if (S.bad)
      return bad(
        "Some saved cards could not be decrypted, so the password can not be changed safely. Tap refresh first.",
      );
    if (n1.length < 8) return bad("Use at least 8 characters.");
    if (n1 !== n2) return bad("The new passwords do not match.");
    setBusy(btn, true, "Re-encrypting…");
    try {
      await S.queue; // finish background saves first, so every card is re-encrypted
      if (!S.token) return;
      var cur = await VaultCrypto.derive(oldPw, S.salt, CFG.PBKDF2_ITERATIONS);
      if (cur.token !== S.token) return bad("Current password is wrong.");
      var salt = VaultCrypto.randomSalt();
      var nd = await VaultCrypto.derive(n1, salt, CFG.PBKDF2_ITERATIONS);
      var items = [];
      for (var c of S.cards)
        items.push({
          id: c.id,
          payload: await VaultCrypto.encrypt(nd.key, {
            title: c.title,
            subs: c.subs,
          }),
        });
      var verifier = await VaultCrypto.encrypt(nd.key, "vault-ok");
      await apiAuthed("rekey", {
        newSalt: salt,
        newToken: nd.token,
        newVerifier: verifier,
        items: items,
      });
      items.forEach(function (it) {
        var r = S.rows.get(it.id);
        if (r) r.payload = it.payload;
      });
      S.key = nd.key;
      S.token = nd.token;
      S.salt = salt;
      S.verifier = verifier;
      S.pubPromise = null;
      persistCache();
      modal("changePwModal").hide();
      ["cpOld", "cpNew", "cpNew2"].forEach(function (id) {
        $("#" + id).value = "";
      });
      toast(
        "Master password changed. Other devices will ask for the new one.",
        "success",
      );
    } catch (e) {
      if (e && e.userMsg) bad(e.userMsg);
      else if (!(e && e.handled)) {
        console.error(e);
        bad("Something went wrong.");
      }
    } finally {
      setBusy(btn, false);
    }
  }

  /* ------------------------------ PWA bits ------------------------------ */
  function registerSW() {
    if ("serviceWorker" in navigator) {
      window.addEventListener("load", function () {
        navigator.serviceWorker
          .register("service-worker.js")
          .catch(function (e) {
            console.warn("SW failed", e);
          });
      });
    }
  }
  var isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
  var isStandalone =
    window.matchMedia("(display-mode: standalone)").matches ||
    window.navigator.standalone;
  function showInstall(on) {
    ["installBtn", "installBtn2"].forEach(function (id) {
      show(id, on);
    });
  }
  async function doInstall() {
    if (S.installEvt) {
      S.installEvt.prompt();
      await S.installEvt.userChoice;
      S.installEvt = null;
      showInstall(false);
    } else if (isIOS)
      toast("In Safari tap Share, then “Add to Home Screen”.", "dark");
  }

  /* ------------------------------ Wiring ------------------------------ */
  function bindUI() {
    $("#lockForm").addEventListener("submit", onLockSubmit);
    $("#revealForm").addEventListener("submit", onRevealSubmit);
    $("#changePwForm").addEventListener("submit", onChangePw);
    $("#retryBtn").addEventListener("click", function () {
      location.reload();
    });
    $("#lockPw").addEventListener("input", function (e) {
      if (S.mode === "setup")
        updateStrength(
          $("#lockStrength"),
          e.target.value,
          $("#lockStrengthText"),
        );
    });
    $("#cpNew").addEventListener("input", function (e) {
      updateStrength($("#cpStrength"), e.target.value);
    });

    var st;
    $("#search").addEventListener("input", function (e) {
      clearTimeout(st);
      st = setTimeout(function () {
        S.query = e.target.value;
        render();
      }, 80);
    });
    $("#clearSearch").addEventListener("click", function () {
      $("#search").value = "";
      S.query = "";
      render();
      $("#search").focus();
    });

    $("#fab").addEventListener("click", function () {
      newCard("");
    });
    $("#syncBtn").addEventListener("click", function () {
      sync(false);
    });
    $("#lockBtnTop").addEventListener("click", function () {
      lock();
    });
    $("#lockNowBtn").addEventListener("click", function () {
      lock();
    });
    $("#hideNow").addEventListener("click", function () {
      hideAll(false);
    });
    $("#deleteConfirm").addEventListener("click", confirmDelete);
    $("#installBtn").addEventListener("click", doInstall);
    $("#installBtn2").addEventListener("click", doInstall);

    $("#settingsBtn").addEventListener("click", function () {
      $("#askRevealSwitch").checked = askReveal();
      $("#themeSelect").value = getPref("vault.theme", "auto");
      modal("settingsModal").show();
    });
    $("#askRevealSwitch").addEventListener("change", function (e) {
      setPref("vault.askReveal", e.target.checked ? "1" : "0");
      if (e.target.checked) {
        S.revealUntil = 0;
        S.expanded.clear();
        S.shown.clear();
      }
      render();
    });
    $("#themeSelect").addEventListener("change", function (e) {
      if (e.target.value === "auto") {
        try {
          localStorage.removeItem("vault.theme");
        } catch (x) {}
      } else setPref("vault.theme", e.target.value);
      window.applyTheme();
    });
    $("#changePwBtn").addEventListener("click", function () {
      modal("settingsModal").hide();
      ["cpOld", "cpNew", "cpNew2"].forEach(function (id) {
        $("#" + id).value = "";
      });
      $("#cpError").classList.add("d-none");
      updateStrength($("#cpStrength"), "");
      setTimeout(function () {
        modal("changePwModal").show();
      }, 250);
    });

    ["revealModal", "changePwModal"].forEach(function (id) {
      document
        .getElementById(id)
        .addEventListener("shown.bs.modal", function () {
          var i = this.querySelector("input");
          if (i) i.focus();
        });
    });

    // password show/hide buttons
    document.addEventListener("click", function (e) {
      var b = e.target.closest("[data-toggle-pw]");
      if (!b) return;
      var inp = document.getElementById(b.dataset.togglePw),
        show = inp.type === "password";
      inp.type = show ? "text" : "password";
      b.querySelector("i").className =
        "bi " + (show ? "bi-eye-slash" : "bi-eye");
    });

    // card list: click / keyboard delegation
    var list = $("#cardList");
    list.addEventListener("click", function (e) {
      var t = e.target.closest("[data-action]");
      if (!t || !list.contains(t)) return;
      var action = t.dataset.action,
        cardEl = t.closest("[data-card]"),
        cardId = cardEl && cardEl.dataset.card;
      var d = S.draft,
        sub =
          d &&
          d.card.subs.find(function (s) {
            return s.id === t.dataset.sub;
          });
      switch (action) {
        case "open":
          openCard(cardId);
          break;
        case "close":
          S.expanded.delete(cardId);
          S.shown.clear();
          render();
          break;
        case "edit":
          startEdit(cardId);
          break;
        case "delete":
          askDelete(t.dataset.id);
          break;
        case "cancel":
          S.draft = null;
          render();
          break;
        case "save":
          saveDraft();
          break;
        case "newFromSearch":
          var q = S.query.trim();
          $("#search").value = "";
          S.query = "";
          newCard(q);
          break;
        case "addSub":
          if (d) {
            var ns = mkSub();
            d.card.subs.push(ns);
            S.focusSel = '[data-bind="subName"][data-sub="' + ns.id + '"]';
            render();
          }
          break;
        case "removeSub":
          if (d) {
            d.card.subs = d.card.subs.filter(function (s) {
              return s.id !== t.dataset.sub;
            });
            render();
          }
          break;
        case "addField":
          if (sub) {
            var nf = mkField();
            sub.fields.push(nf);
            S.focusSel = '[data-bind="fLabel"][data-field="' + nf.id + '"]';
            render();
          }
          break;
        case "removeField":
          if (sub) {
            sub.fields = sub.fields.filter(function (f) {
              return f.id !== t.dataset.field;
            });
            render();
          }
          break;
        case "eye": {
          var fe = t.closest(".field"),
            se = t.closest("[data-sub]");
          if (fe && se) toggleEye(fe, se.dataset.sub, fe.dataset.field);
          break;
        }
        case "copy": {
          var fe2 = t.closest(".field"),
            se2 = t.closest("[data-sub]");
          if (fe2 && se2) copyValue(se2.dataset.sub, fe2.dataset.field);
          break;
        }
      }
    });
    list.addEventListener("keydown", function (e) {
      if (
        (e.key === "Enter" || e.key === " ") &&
        e.target.matches("article.closed")
      ) {
        e.preventDefault();
        openCard(e.target.dataset.card);
      }
    });
    list.addEventListener("input", function (e) {
      var t = e.target,
        b = t.dataset.bind;
      if (!b || !S.draft) return;
      var c = S.draft.card;
      if (b === "title") {
        c.title = t.value;
        return;
      }
      var s = c.subs.find(function (x) {
        return x.id === t.dataset.sub;
      });
      if (!s) return;
      if (b === "subName") s.name = t.value;
      else {
        var f = s.fields.find(function (x) {
          return x.id === t.dataset.field;
        });
        if (f) {
          if (b === "fLabel") f.label = t.value;
          else f.value = t.value;
        }
      }
    });

    // inactivity tracking
    ["pointerdown", "keydown", "input", "touchstart"].forEach(function (ev) {
      document.addEventListener(ev, onActivity, { passive: true });
    });
    window.addEventListener("scroll", onActivity, { passive: true });
    setInterval(tick, 1000);
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) S.hiddenAt = Date.now();
      else if (S.key) {
        if (Date.now() - S.hiddenAt > 60000)
          lock("Locked while you were away.");
        else {
          tick();
          if (Date.now() - S.lastSync > 180000) sync(true);
        } // quiet refresh after a while
      }
    });

    window.addEventListener("beforeinstallprompt", function (e) {
      e.preventDefault();
      S.installEvt = e;
      showInstall(true);
    });
    window.addEventListener("appinstalled", function () {
      showInstall(false);
      toast("App installed.", "success");
    });
    if (isIOS && !isStandalone) showInstall(true);
    window.addEventListener("online", function () {
      if (S.key) sync(true);
    });
    // warn before closing the tab while a save is still on its way to Google
    window.addEventListener("beforeunload", function (e) {
      if (S.pending) {
        e.preventDefault();
        e.returnValue = "";
      }
    });
  }

  init();
})();

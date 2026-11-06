// The only code CipherMoth ever runs inside a web page. It is injected with
// scripting.executeScript into the top frame's isolated world, only after the
// user asked for a fill (popup click or keyboard shortcut), and gets the login
// as its arguments. It must stay one self-contained function: the browser
// serializes it, so it can use nothing from outside its own body.
//
// What it guarantees: nothing is filled unless this is the top frame of the
// origin the popup matched (checked again here, after any navigation), and only
// fields a person can see and use get a value. It never submits, never clicks,
// never reads a field's value and returns no values. What it cannot guarantee:
// a page on the right origin owns its own fields and can read what was filled.

export interface FillRequest {
  origin: string;
  username: string | null;
  password: string | null;
}

export interface FillResult {
  filled: ("username" | "password")[];
  reason:
    | "filled"
    | "username-only"
    | "password-only"
    | "no-fields"
    | "new-password"
    | "hidden"
    | "origin"
    | "frame";
}

export function fillLogin(request: FillRequest): FillResult {
  if (window.top !== window) return { filled: [], reason: "frame" };
  if (location.origin !== request.origin) return { filled: [], reason: "origin" };

  const MIN_SIZE = 8;
  const MIN_OPACITY = 0.1;
  const TEXT_TYPES = new Set(["text", "email", "tel", ""]);

  const tokens = (input: HTMLInputElement): string[] =>
    (input.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).filter(Boolean);

  // Every <input> of the top document, including open shadow roots, in tree
  // order. Closed shadow roots and frames are out of reach by design.
  const inputs: HTMLInputElement[] = [];
  const walk = (root: Document | ShadowRoot): void => {
    const elements = root.querySelectorAll("*");
    for (const element of Array.from(elements)) {
      if (element instanceof HTMLInputElement) inputs.push(element);
      if (element.shadowRoot) walk(element.shadowRoot);
    }
  };
  walk(document);

  // The element's ancestors across shadow boundaries.
  const ancestors = (element: Element): Element[] => {
    const chain: Element[] = [];
    let node: Node | null = element;
    while (node) {
      if (node instanceof Element) chain.push(node);
      const parent: Node | null = node.parentNode;
      node = parent instanceof ShadowRoot ? parent.host : parent;
    }
    return chain;
  };

  const inViewport = (rect: DOMRect): boolean =>
    rect.top >= 0 &&
    rect.left >= 0 &&
    rect.bottom <= window.innerHeight &&
    rect.right <= window.innerWidth;

  const usable = (input: HTMLInputElement): boolean => {
    if (!input.isConnected || input.disabled || input.readOnly) return false;
    if (input.type === "hidden") return false;
    const chain = ancestors(input);
    let opacity = 1;
    for (const element of chain) {
      if (element.getAttribute("aria-hidden") === "true") return false;
      if (element.hasAttribute("inert") || element.hasAttribute("hidden")) return false;
      const style = getComputedStyle(element);
      if (style.display === "none") return false;
      if (style.visibility === "hidden" || style.visibility === "collapse") return false;
      if (style.contentVisibility === "hidden") return false;
      // Masks and filters hide a field without changing what a click reaches.
      const mask = style.maskImage || style.getPropertyValue("-webkit-mask-image");
      if (mask && mask !== "none") return false;
      for (const match of (style.filter || "").matchAll(/opacity\(([\d.]+)(%?)\)/g)) {
        opacity *= Number.parseFloat(match[1] ?? "1") / (match[2] ? 100 : 1);
      }
      opacity *= Number.parseFloat(style.opacity || "1");
    }
    if (!(opacity >= MIN_OPACITY)) return false;
    if (
      typeof input.checkVisibility === "function" &&
      !input.checkVisibility({ opacityProperty: true, visibilityProperty: true })
    )
      return false;
    let rect = input.getBoundingClientRect();
    if (rect.width < MIN_SIZE || rect.height < MIN_SIZE) return false;
    if (!inViewport(rect)) {
      input.scrollIntoView({ block: "center", inline: "nearest" });
      rect = input.getBoundingClientRect();
      if (!inViewport(rect)) return false;
    }
    // Not covered or clipped at its centre: what a click there would reach must
    // be the field itself. Clip paths, masks and overlays all fail here.
    const root = input.getRootNode() as Document | ShadowRoot;
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const hit = root.elementFromPoint(x, y);
    return hit === input || (hit !== null && input.contains(hit));
  };

  const passwordFields = inputs.filter((input) => input.type === "password");
  const current = passwordFields.filter((input) => tokens(input).includes("current-password"));
  const fresh = passwordFields.filter((input) => tokens(input).includes("new-password"));
  const candidates = (current.length ? current : passwordFields).filter(
    (input) => !tokens(input).includes("new-password")
  );
  const passwordField = candidates.find(usable) ?? null;

  const isUsernameLike = (input: HTMLInputElement): boolean => {
    const auto = tokens(input);
    if (auto.includes("username") || auto.includes("email")) return true;
    if (!TEXT_TYPES.has(input.type)) return false;
    if (input.type === "email") return true;
    const hints = `${input.name} ${input.id} ${input.getAttribute("aria-label") || ""}`;
    return /user|email|e-mail|login|account|identifier/i.test(hints);
  };

  let usernameField: HTMLInputElement | null = null;
  if (request.username) {
    if (passwordField) {
      const form = passwordField.form;
      const before = inputs.filter(
        (input) =>
          input !== passwordField &&
          input.form === form &&
          passwordField.compareDocumentPosition(input) & Node.DOCUMENT_POSITION_PRECEDING
      );
      // Without a form, every formless input on the page counts as "before":
      // only a field that says it is a username may take it (never a header
      // search box).
      const plausible = (input: HTMLInputElement): boolean =>
        form ? TEXT_TYPES.has(input.type) || input.type === "email" : isUsernameLike(input);
      usernameField =
        before.find((input) => {
          const auto = tokens(input);
          return (auto.includes("username") || auto.includes("email")) && usable(input);
        }) ??
        before.reverse().find((input) => plausible(input) && usable(input)) ??
        null;
    } else if (fresh.length === 0) {
      // A username-first step of a multi-step login (Google, Amazon and others
      // keep a hidden password field there for password managers). Never on a
      // sign-up or password-change form, which has new-password fields.
      usernameField = inputs.find((input) => isUsernameLike(input) && usable(input)) ?? null;
    }
  }

  if (!passwordField && !usernameField) {
    if (fresh.length) return { filled: [], reason: "new-password" };
    const anyLoginField = passwordFields.length > 0 || inputs.some(isUsernameLike);
    if (anyLoginField) return { filled: [], reason: "hidden" };
    // Nothing to fill here; frames are never filled, so say so when there are
    // some (the login form is probably in one, as on Apple ID).
    const framed = document.querySelector("iframe, frame") !== null;
    return { filled: [], reason: framed ? "frame" : "no-fields" };
  }

  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  const place = (input: HTMLInputElement, value: string): void => {
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const filled: FillResult["filled"] = [];
  if (usernameField && request.username) {
    place(usernameField, request.username);
    filled.push("username");
  }
  if (passwordField && request.password !== null) {
    place(passwordField, request.password);
    filled.push("password");
  }
  if (filled.length === 2) return { filled, reason: "filled" };
  if (filled[0] === "username") return { filled, reason: "username-only" };
  if (filled[0] === "password") return { filled, reason: "password-only" };
  return { filled, reason: "no-fields" };
}

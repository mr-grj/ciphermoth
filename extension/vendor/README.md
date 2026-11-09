# Vendored packages

Patched copies of development dependencies whose fix is not released. Each is
a root `devDependency` (`file:vendor/...`) that `overrides` in `../package.json`
puts in place of the published package everywhere in the tree. Remove a copy
(its `devDependencies` entry and its override) as soon as a fixed release
exists. None of this code is part of the extension packages.

## deepmerge

`web-ext` uses `addons-linter`, which uses `deepmerge` 4.3.1, affected by
GHSA-gcqx-w48m-w2h4 (prototype poisoning in `mergeObject()`: an own
`__proto__` key, as `JSON.parse` creates, replaced the result's prototype).
No fixed release exists.

This is the published 4.3.1 package with one change in `index.js`,
`dist/cjs.js` and `dist/umd.js`: merged keys are written with
`Object.defineProperty` as own data properties (`defineOwn`), so `__proto__`
is copied as data and never runs the setter; other keys behave as before.
`package.json` has version `4.3.2-ciphermoth.1` and no `devDependencies` or
`scripts` (the built `dist` files are used as published). MIT licensed, see
`license.txt`.

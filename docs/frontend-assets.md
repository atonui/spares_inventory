# Frontend CSS assets

Readable styles live in `static/*.css`. The generated copies in
`static/minified/` are committed so the Python production runtime needs no Node build.

After editing a source stylesheet:

```sh
npm ci --ignore-scripts
npm run build:css
npm run check:css
```

Commit both the source and generated changes. The frontend-assets CI workflow rejects
stale generated CSS. Do not edit generated files directly.

The static server serves generated CSS at the existing source stylesheet URL,
preserving relative font/image paths. Custom styles without a generated copy fall
back to their source. Minification uses pinned clean-css with level 1 only and URL
rebasing disabled.

When a visual stylesheet change is made, update its version query in affected HTML
as before. Minification alone preserves styling, so existing cached source responses
remain valid and new requests receive the smaller representation.

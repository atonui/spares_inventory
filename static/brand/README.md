# Spares Tracker brand assets

The approved asset pack in this directory is the source of truth for the public product identity. Do not redraw, distort, recolor, or replace the S-shaped tracking-route mark.

## Palette

- Navy: `#15263B`
- Amber: `#E9A23B`
- Slate: `#64748B`
- Pale neutral: `#F5F7FA`
- White: `#FFFFFF`

Use amber as an accent. Use navy on amber for text and controls; amber on white is not suitable for normal text. Keep stock, warning, error, and success colors distinct from brand accents.

## Supplied source files

- `source/logo-color.svg`, `logo-black.svg`, `logo-white.svg` — wordmark variants.
- `source/mark-color.svg`, `mark-black.svg`, `mark-white.svg` — supplied route mark variants.
- `source/logo-*.png` and `logo-color.jpg` — supplied raster wordmarks.
- `source/favicon.svg` — supplied vector favicon.
- `generated/favicon-*.png`, `favicon.ico`, and `apple-touch-icon.png` — supplied web icon exports.
- `generated/app-icon-*.png` and platform layers — supplied mobile icon exports.

The web UI uses the supplied white wordmark on navy and color mark on pale or white surfaces. The Expo app uses the supplied `mobile/assets/icon.png` plus supplied Android adaptive layers.

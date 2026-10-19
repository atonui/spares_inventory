# Spares Tracker brand assets

Spares Tracker is the current public-facing product name. Repository, package, bundle, and URL identifiers remain unchanged.

## Editable SVG sources

- `source/logo-horizontal.svg` — shelf mark with the wordmark as live SVG text.
- `source/logo-icon.svg` — icon-only mark for light surfaces.
- `source/app-icon-square.svg` — square navy app-icon master.
- `source/adaptive-icon-foreground.svg` — transparent foreground for Android adaptive icons.
- `source/favicon.svg` — browser favicon source.

The wordmark shown in the web UI is HTML text next to an inline SVG icon. App icons contain only the shelf symbol.

## Exports

- `generated/app-icon-1024.png` and `generated/app-icon-512.png` — raster exports from `app-icon-square.svg`.
- `generated/favicon-{16,32,48}.png` and `generated/favicon.ico` — web favicon exports.
- `generated/apple-touch-icon.png` — iOS home-screen icon.
- `mobile/assets/icon.png` — iOS and general app icon.
- `mobile/assets/android-icon-foreground.png`, `android-icon-background.png`, and `android-icon-monochrome.png` — Android adaptive icon layers.
- `mobile/assets/favicon.png` — Expo web favicon.
- `mobile/assets/splash-icon.png` — transparent shelf mark from `logo-icon.svg`.

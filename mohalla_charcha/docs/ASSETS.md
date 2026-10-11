# Assets and licenses

## Original brand

`assets/branding/logo.svg` is the editable master: a home in a conversation, with a second sage-green neighbour bubble. Original geometric vector paths are defined in `scripts/generate_branding.py`; this logo is **hand-coded vector artwork**, not an AI-generated photograph.

`logo.png` is 1024×1024. The same master produces density-specific Android launcher PNGs, Android8+ adaptive foreground, legacy/Android12+ splash vectors, web192/512 icons and favicon. Regeneration is optional: install `CairoSVG==2.8.2` and run the script. Committed outputs are sufficient to build; CairoSVG is **not** a Flutter/CI runtime dependency.

Brand source/paths are covered by the project's MIT license. This is not a trademark clearance or an official Bihar/government emblem. Brand colours: terracotta `#BD5337`, sage `#39765D`, ivory `#F6F7F3`.

## Fonts

- Manrope 400/500/600/700/800: Google Fonts variable source instantiated at each weight; bundled SIL Open Font License `Manrope-OFL.txt`.
- Noto Sans Devanagari 400/500/600/700/800: Google Fonts variable source, standard width; bundled SIL OFL `NotoSansDevanagari-OFL.txt`.

## Illustrative media

- `assets/images/neighborhood.jpg`: AI-generated editorial neighbourhood illustration, reused in welcome/feed.
- `waterlogging.jpg`: fictional AI-generated civic-lane photo.
- `chai.jpg`: fictional AI-generated tea-shop photo.
- Welcome maps/people motifs: local Flutter vector/icon drawings, not actual geographic boundaries or a live conversation.

Photos are not evidence of a real incident/shop review. Demo people/events/counts/locations are sample data. Use authentic, consented content and verified master data for launch.

Fonts/images/logo are bundled: no Google Fonts/CDN call for default UI. Opt-in OpenStreetMap tiles require internet/attribution and a traffic-appropriate production provider.

# SEO/name decision — 12 October 2026

## Final approved name

**Bihar Local - Mohalla Charcha** — **29 characters**, including spaces and the hyphen. The earlier colon variant was28; this requested hyphen variant is29. Both fit Google Play's30-character maximum. [1](https://support.google.com/googleplay/android-developer/answer/13393723?hl=en)

Primary wordmark: **Bihar Local**. Secondary brand: **Mohalla Charcha**. Existing home/conversation logo geometry retained.

This was the user's approved fallback if no clearer, better-fitting alternative emerged. It is a relevance/positioning decision, **not a measured search-volume winner or trademark clearance**.

## What was checked

Public web/Play search-result samples for:

- `Bihar local community app`
- `Bihar Local Mohalla Charcha` and the exact requested title
- `Bihar community app local updates reviews events`
- `Bihar local news app Patna`

Observed intent, not monthly-volume figures:

- `Bihar local/news` samples return news-publisher/news-app material, including Prabhat Khabar and dedicated Bihar-news apps. Those are a different product promise from our neighbour discussions/reviews/events. [1](https://www.prabhatkhabar.com/state/bihar) [1](https://play.google.com/store/apps/details?id=app.bharatbrief.biharnews&hl=en_US)
- Broad Bihar/community samples mix government services, local information and matchmaking. “Bihar Lokal Matrimony” is an existing, differently purposed listing, so copying that spelling/positioning would not clarify this P2P app. [4](https://play.google.com/store/apps/details?id=get.lokal.biharmatrimony) [2](https://play.google.com/store/apps/details?id=com.bihar.biharsharifnagarnigam&hl=en-US)
- The limited sample did not establish a better-fitting replacement for the agreed geography-plus-brand title. Absence of an exact result is **not proof of availability, uniqueness or trademark ownership**.

**Not obtained:** exact India/Hindi/English Play keyword volumes, monthly Google search counts, paid-ASO difficulty estimates or a statistically valid market comparison. There are no fabricated scores/numbers in `seo/keyword-map.csv`.

## Keyword map

[CSV](../seo/keyword-map.csv) separates app-relevant intents from unsupported traffic terms.

| Role | Phrases to use naturally | Why |
|---|---|---|
| Brand | Bihar Local Mohalla Charcha; Mohalla Charcha | Find/recognise this product |
| Core | Bihar local community app; Bihar community app | Regional P2P community, qualified by functionality |
| Neighbourhood | mohalla community; पड़ोस की चर्चा; बिहार स्थानीय समुदाय | Actual conversations/community purpose |
| Features | local shop reviews Bihar; community events Bihar; ward community Bihar | Existing typed-post functionality |
| Later real content | Patna community app; Gaya local community; Patna local events | Only when useful actual public content is available |

These are **research hypotheses/relevance assessments**, not confirmed high-volume phrases. Avoid “Sarkari Yojana”, “Jobs”, “Dating”, “Breaking News” as promises: those are not implemented core services. Google Play requires truthful, relevant metadata and disallows repetitive/irrelevant keyword stuffing. [2](https://support.google.com/googleplay/android-developer/answer/9898842)

## Google SEO: tags are not all ranking signals

**Do not add a `meta keywords` list.** Google Search ignores it; it has no effect on indexing/ranking. [1](https://developers.google.com/search/docs/crawling-indexing/special-tags)

Implemented instead:

- Descriptive `<title>`: `Bihar Local - Mohalla Charcha | Bihar Community App`.
- Accurate meta description; useful visible heading/body copy in English and Hindi.
- One visible H1 on a substantive **static HTML landing page** `web/discover/index.html`; it does not require Flutter/JavaScript to read. The Flutter app remains at the root.
- Open Graph/Twitter sharing metadata, app/PWA name and Android native display label.
- `SoftwareApplication` JSON-LD with true identity/functionality. No invented ratings, price, publisher, download link or rich-result promise.
- FAQ copy explaining P2P/no government routing, no professional breaking-news promise, manual location and current demo state.
- No empty automated city/ward “doorway” pages and no private-profile/phone indexing.

Google may use a description for snippets, but a meta description is not a guaranteed ranking boost. Useful page content matters. [5](https://developers.google.com/search/docs/fundamentals/seo-starter-guide)

## Store listing files

- [`store/listing_en-IN.json`](../store/listing_en-IN.json):29-character title,76-character short description.
- [`store/listing_hi-IN.json`](../store/listing_hi-IN.json): same recognisable title,73-character Hindi short description.
- Both full descriptions below4000 characters and explicitly identify the current preview/demo.
- Suggested **category: Social**. In Play Console, pick only genuinely applicable **predefined tags** offered there. The keyword CSV is not a custom Play-tag upload list. Category/tags are set in Play Console; they are not changed by editing Dart. [4](https://support.google.com/googleplay/android-developer/answer/9859152?hl=en)

Store title/description limits do not mean a Play listing was published. These are ready-to-use drafts. Switch demo wording only after live functionality/launch gates are actually completed.

## Identity and update safety

Source of truth: [`branding/app_identity.json`](../branding/app_identity.json).

```bash
python3 scripts/sync_identity.py
python3 scripts/sync_identity.py --check
```

Generated files: `lib/config/app_identity.dart`, Android `values/strings.xml`, web metadata/manifest and static landing page. UI uses `BrandWordmark`; shared-post summaries and Telegram ZIP labels use the new name.

**Unchanged:** Android ID `in.mohallacharcha.app`, preference keys (`mohalla.demo.v1`, welcome/language/saved state), database/table/RPC names and project folder. This is a display rebrand, not a separate application/account migration. Version1.2.0. Stable release-signing key is still necessary for updatable APKs.

## What still needs a real public domain / publication

No actual website domain or published Play URL was supplied. Therefore **no fake canonical, sitemap, store link or Search Console verification token was added**.

1. Deploy the built web files on your real public HTTPS domain.
2. Set its base URL in `branding/app_identity.json` → `site_url`.
3. Sync again: real root/discover canonicals, robots sitemap link and `web/sitemap.xml` are generated. No extra empty pages are generated.
4. Rebuild/deploy, then verify your site in Google Search Console and submit the sitemap.
5. Link the real published Play listing only when it exists. Keep URLs/city content useful and privacy-safe.
6. Monitor impressions/queries/clicks and store-listing conversion; do not optimise merely for unrelated traffic.

Google's SEO guidance does **not** guarantee first rank. No title/tag combination can promise it. [1](https://developers.google.com/search/docs/fundamentals/do-i-need-seo)

## Validation scope

This rename is checked with actual Flutter/analyzer/widget tests and Python metadata/identity/static-HTML tests. A website ranking, public indexation, Play publication, trademark clearance and new Telegram delivery are **not** implied. See [validation history](VALIDATION.md) for the earlier v1.1 build/remote status.

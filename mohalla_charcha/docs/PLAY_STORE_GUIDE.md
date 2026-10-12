# Play Store release guide (review na fasne ka checklist)

Yeh guide Bihar Local v1.3.0+ ke Play Store submission ke liye hai. Har section
Google Play Console ke jawaab aur is codebase me unse linkd features ka
concise reference deta hai. Privacy ka poora text docs/PRIVACY_POLICY.md me
hain — use Telegra.ph/GitHub Pages pe host karke URL daalo.

## Review ke 3 sabse bade gunhe pehle se bund karo

| Risk | Status this codebase |
|---|---|
| **Account deletion nahi hai** (2024 se hard required) | ✅ Imp: `bl_delete_my_account()` RPC (migration `202610120002`) + Profile → "अकाउंट डिलीट करें" button. SQL tests 04 pass. |
| **targetSdk purana** (Oct 2026 policy = API 36) | ✅ `android/app/build.gradle.kts` me `targetSdk = 36` pin kiya. compileSdk bhi 36 (Flutter 3.35.4 default). |
| **UGC (user-generated content) policy** | ✅ In-app Report 🔨, community moderator model (`bl_moderate_post`, audited), posts hide, block/report documented. Listing me "UGC moderation active" likho. |

## Play Console — Data safety form (answers)

| Question | Answer | Why (code ref) |
|---|---|---|
| App me personal user data collect hota hai? | Yes: **App activity** (posts/comments/reactions), **Personal info** (name aap dena choose kare), **Photos** (user uploads) | `bl_posts`, `bl_post_reactions`, `bl-post-media` bucket |
| Precise location? | **No** — sirf ward + approx pins (~100 m rounding) | `_stamp_location` SQL trigger, no GPS permission |
| Phone / email / contacts / device IDs? | **No** | anonymous guest login (no OTP), manifest sirf INTERNET |
| Data encrypted in transit? | **Yes** — HTTPS only (Supabase) | — |
| Data deletion available? | **Yes — in-app** | Profile → "अकाउंट डिलीट करें" |
| Collected data shared with third parties? | **No** | destinations sirf Supabase project |
| Anonymized/deidentified analytics? | **No** — koi analytics SDK nahi | pubspec inspect |

## Content rating (esteri palak)

- Everyone 13+ (User-Generated Content). Teen-safety: koi private chat nahi hai
  — sirf public ward threads — isse "child safety" risk questions simple rakh.

## Personal and Sensitive User Data policy (media)

v1.3.1 se photos upload hone se PEHLE bhi app ke andar compress hoti hain (~0.3 MB JPEG, 1280px) aur EXIF/GPS metadata bhi remove hota hai — privacy dialog me disclose kiya gaya hai. Store listing description me yeh privacy feature likhna review ko strong banata hai. Storage budget bhi chhota (bucket limit 1.5 MB, migration 03).

## Release steps (1st time)

1. ✅ Root workflow FIXED — fresh `Run workflow` se universal APK banega
   aur ZIP Telegram pe aayega (TESTING ke liye). **Abhi APK kaafi hai.**
   Play submission ke time par **AAB** banana hoga — workflow me ek
   `flutter build appbundle --release` step add hota hai; woh file tab
   denge, web editor se paste kar lena.
2. **Signing**: Play App Signing ke liye ORIGINAL upload keystore zaroori hai
   (ek hi baar generate, hamesha safe rakho → `ANDROID_KEYSTORE_BASE64`,
   `ANDROID_STORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`
   secrets me asli values). Workflow me `require_signing: true` chalao tab.
   **Abhi signing nahi chahiye** — testing APK unsigned/debug-signed bhi
   chal jayegi.
3. Store listing assets already repo me hain: `store/listing_en-IN.json`,
   `store/listing_hi-IN.json`, `seo/`, adaptive icons `assets/branding/`.
4. Play Console → Privacy policy URL: docs/PRIVACY_POLICY.md ka hosted link (operator email pehle se bhara hai — contact = nitesh.skyhigh@gmail.com).
5. Internal testing track pe pehle daudo, firo production.

## Annoying review-milne wale sawaalaaw (aapke paas answers ready)

- "Why hole ward?" → hyperlocal scope, home-ward-first feature, feed
  `bl_get_feed` geoscoped.
- "Anonymous login scam-like kyun?" → No-credentials guest login; community
  P2P; data minimization (policy citation).
- "Moderation kaise chalti?" → volunteers + `bl_moderation_log` audit + report
  uniqueness (docs/SUPABASE_SETUP.md §5).

# Jungle Strike 3D (Godot migration prototype)

This is the start of a Godot 4 third-person, offline campaign version. It is a playable 3D greybox foundation, not finished BGMI-level art or a production Android build yet.

## Current prototype

- Godot 4 project using the mobile-friendly Compatibility renderer.
- Third-person CharacterBody3D movement, jump, orbit camera and hitscan firing.
- Procedurally assembled jungle cover, simple ridgelines, atmospheric sky and muzzle flash light.
- Desktop test controls: WASD move, mouse look, left click or F fire, Space jump.

## Migration plan

Keep the existing Flutter build intact until this Godot project can export, install and run on Android. Then migrate the campaign, touch controls, save/checkpoint system, missions, weapon progression and Telegram APK ZIP delivery; only then retire Flutter. Reaching BGMI-like visual quality also requires authored/licensed 3D character, weapon, animation, terrain and effects assets, plus device profiling and optimization. This greybox is intentionally not presented as that final quality level.

Open `project.godot` with Godot 4.4 or newer. Godot is not installed in the current sandbox, so this project has not yet been engine-validated or exported as an APK.

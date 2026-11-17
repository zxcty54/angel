# The Blackout Tower (Godot 4)

An offline, single-player third-person action campaign. Ex-agent and experimental Kinetic Suit operator fights upward through 50 floors of an autonomous research tower after the Helix AI seals the facility. Dr. Mira Sen sends short radio guidance; encrypted revelations arrive every second floor. The story centers on the lockdown, the protagonist's missing memories, and what Helix is protecting.

## Play loop

- Clear security details on each modular tower floor; every tenth floor ends in a heavy-unit boss encounter.
- Pick a suit upgrade at chapter breaks, retry from the current floor after death, and save unlocked progress locally.
- Desktop: WASD move, mouse aim, left-click or F fire, Space jump. Mobile builds include the on-screen movement and combat controls.
- Built from procedural facility geometry and simple character meshes. This is a polished gameplay prototype, not BGMI/COD-grade authored art; production character, weapon and animation assets, sound, accessibility work, device QA and performance profiling are still future work.

Open `project.godot` with Godot 4.4 or newer. The GitHub workflow exports the Android APK, packages it as a ZIP, and delivers the ZIP to the configured Telegram destination; it does not publish an APK artifact on GitHub.

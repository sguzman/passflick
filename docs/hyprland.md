# Hyprland integration

Passflick is an independent Wayland application with app ID `passflick`. Its window should float and center without rearranging tiled workspaces. Hyprland owns that decision; the application does not edit compositor configuration.

## Floating window rule

Use the syntax appropriate to your installed Hyprland version.

**Hyprland 0.55+ (Lua):**

```lua
hl.window_rule({
  name = "passflick-picker",
  match = { class = "^(passflick)$" },
  float = true,
  center = true,
})
```

**Hyprland 0.53–0.54 (hyprlang):**

```ini
windowrule = match:class ^(passflick)$, float on, center on
```

**Older hyprlang configurations:**

```ini
windowrulev2 = float, class:^(passflick)$
windowrulev2 = center, class:^(passflick)$
```

The **Vaultwarden preview is a separate window class**: its Rust viewport declares the Wayland app ID `passflick-projection-preview`, whereas the historical default picker uses `passflick`. A float/center rule matching only `passflick` therefore does **not** cover the preview. On Hyprland versions supporting the Lua rule syntax above, add this opt-in rule *alongside* the historical rule:

```lua
hl.window_rule({
  name = "passflick-projection-preview",
  match = { class = "^(passflick-projection-preview)$" },
  float = true,
  center = true,
})
```

Only use the syntax supported by your installed compositor. Confirm the **actual** `class` and focus behavior through `hyprctl clients`. The target host has now demonstrated real preview window launch, focused search, credential copying and same-session cache reuse, but precise float/center placement and close-to-focus restoration remain to be separately accepted. If your version uses hyprlang, adapt the preview class to the version-specific examples above.

## Summon shortcut

Once the pre-release user installer has placed Passflick at `~/.local/bin/passflick`, a traditional hyprlang keybinding can launch it directly:

```ini
bind = SUPER, P, exec, ~/.local/bin/passflick
```

The graphical desktop entry is also installed for application launchers. Neither path requires a terminal window or resident daemon. A custom XDG binary directory can change the executable path.

### Opt-in Vaultwarden app-menu launcher (Cargo-installed binary)

For the **feature-enabled** Cargo-installed picker, keep the existing `passflick.desktop` and old `passflick` keybinding unchanged. From the repository run:

```fish
fish scripts/install-vaultwarden-launcher.fish
```

This creates only `passflick-vaultwarden.desktop` under the user's XDG `applications` directory. Its `Exec` uses the absolute `~/.cargo/bin/passflick projection picker` path (or an executable in `$CARGO_HOME/bin`), so app-menu launch does not depend on Hyprland inheriting fish's `PATH`. The script refuses to replace an existing launcher, does not copy to `~/.local/bin`, and does not modify any keybindings.

Only after the app menu launches successfully, optionally bind the direct executable and `projection picker` arguments in your *own* Hyprland configuration. Use an unused shortcut of your choosing, never replace an existing binding without reviewing it. Do not use a shell-escaped XDG QA directory or the legacy no-argument command.

**Acceptance gate:** App-menu activation and floating/focus behavior are still unverified in the user's target session, as are logout and clipboard-history security checks. The command-line picker and same-session key reuse are verified.

References: [current Hyprland window rules](https://wiki.hypr.land/Configuring/Basics/Window-Rules/) and [Hyprland 0.54 window rules](https://wiki.hypr.land/0.54.0/Configuring/Window-Rules/).

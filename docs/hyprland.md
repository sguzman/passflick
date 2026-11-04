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

Only use the syntax supported by your installed compositor. Confirm the **actual** `class` and focus behavior through `hyprctl clients`; do not claim that the preview has passed target-host validation. If your version uses hyprlang, adapt the preview class to the version-specific examples above.

## Summon shortcut

Once the pre-release user installer has placed Passflick at `~/.local/bin/passflick`, a traditional hyprlang keybinding can launch it directly:

```ini
bind = SUPER, P, exec, ~/.local/bin/passflick
```

The graphical desktop entry is also installed for application launchers. Neither path requires a terminal window or resident daemon. A custom XDG binary directory can change the executable path.

**Acceptance gate:** Actual floating behavior and focus restoration have not yet been checked in the target Hyprland session.

References: [current Hyprland window rules](https://wiki.hypr.land/Configuring/Basics/Window-Rules/) and [Hyprland 0.54 window rules](https://wiki.hypr.land/0.54.0/Configuring/Window-Rules/).

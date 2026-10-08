# Hyprland integration

Passflick's executable creates a small undecorated always-on-top Wayland window with the app ID `passflick`. Hyprland, not egui, ultimately decides whether that window floats or joins the tiling layout. For reliable summon-and-dismiss behavior, explicitly float and center it.

The following example targets the newer Hyprland window-rule syntax (v0.53 generation, `hyprland.conf`):

```ini
windowrule = match:class ^(passflick)$, float on, center on
```

Older Hyprland releases use different syntax; for v0.46–v0.50 style configuration:

```ini
windowrule = float, class:^(passflick)$
windowrule = center, class:^(passflick)$
```

For configurations using the newer Lua rules interface, an equivalent rule can be declared as:

```lua
hl.window_rule({
  name = "passflick-picker",
  match = { class = "passflick" },
  float = true,
  center = true,
})
```

The release and user configuration determine which syntax applies. Do **not** paste multiple syntaxes together. Check the actual window class with `hyprctl clients` if the rule does not match.

Set a compositor shortcut to invoke the binary directly, for example:

```ini
bind = SUPER, P, exec, passflick
```

Choose your own binding if that conflicts with an existing keymap. No resident daemon is necessary; each invocation opens a fresh picker and exits after the copy action.

References: [Hyprland v0.53 window rules](https://wiki.hypr.land/0.53.0/Configuring/Window-Rules/), [current Hyprland rule reference](https://wiki.hypr.land/configuring/core/rules/window-rules/).

**Acceptance gate:** Actual floating behavior and window-class matching have not yet been verified on the target Hyprland session. Do not claim the application can force the compositor not to tile without that rule.

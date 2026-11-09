#!/usr/bin/env fish
# Opt-in launcher for an already cargo-installed, feature-enabled Passflick.
# Does not copy binaries, edit Hyprland, or replace the legacy launcher.

if test (id -u) -eq 0
    echo "Run as your regular user, not root." >&2
    exit 1
end

set -l binary "$HOME/.cargo/bin/passflick"
if set -q CARGO_HOME; and test -x "$CARGO_HOME/bin/passflick"
    set binary "$CARGO_HOME/bin/passflick"
end
if not test -x "$binary"
    echo "No cargo-installed Passflick found at $binary" >&2
    exit 1
end

# An ordinary cargo install without this feature still has the old picker.
if not "$binary" --help | grep -Fq 'passflick projection <unlock|lock|status|picker>'
    echo "This executable lacks vaultwarden-preview; leaving launchers unchanged." >&2
    exit 1
end

set -l data_home "$HOME/.local/share"
if set -q XDG_DATA_HOME; and test -n "$XDG_DATA_HOME"
    set data_home "$XDG_DATA_HOME"
end
set -l app_dir "$data_home/applications"
set -l target "$app_dir/passflick-vaultwarden.desktop"

# Desktop-entry Exec uses special quoting and %-field codes. Reject names
# with metacharacters instead of writing a misleading or unsafe command.
if string match -rq '["%\x60\x24\\]' -- "$binary"
    echo "The binary path needs desktop-entry escaping; no launcher was written." >&2
    exit 1
end
if test -e "$target"; or test -L "$target"
    echo "Launcher already exists; refusing to overwrite: $target" >&2
    exit 1
end

mkdir -p -- "$app_dir"; or exit 1
set -l staged (mktemp "$app_dir/.passflick-vaultwarden.XXXXXXXX")
if test -z "$staged"
    echo "Unable to create staged desktop entry." >&2
    exit 1
end

printf '%s\n' \
    '[Desktop Entry]' \
    'Type=Application' \
    'Name=Passflick (Vaultwarden)' \
    'GenericName=Offline Password Picker' \
    'Comment=Search your encrypted read-only Vaultwarden projection' \
    "Exec=\"$binary\" projection picker" \
    'Icon=dialog-password' \
    'Terminal=false' \
    'Categories=Utility;Security;' \
    'Keywords=password;vaultwarden;credentials;picker;' \
    'StartupNotify=true' > "$staged"
or begin
    rm -f -- "$staged"
    exit 1
end

chmod 644 "$staged"; or begin
    rm -f -- "$staged"
    exit 1
end
# Atomic create-if-absent; never overwrite an existing desktop entry.
ln -- "$staged" "$target"
set -l result $status
rm -f -- "$staged"
if test $result -ne 0
    echo "Launcher could not be installed without replacement: $target" >&2
    exit 1
end
echo "Installed Vaultwarden launcher: $target"
echo "The historical Passflick launcher and all vault files are unchanged."

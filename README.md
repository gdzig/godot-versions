# Godot Binaries

Zig package manager distribution of Godot Engine binaries.

This repository automatically syncs Godot releases from [godotengine/godot](https://github.com/godotengine/godot) and exposes them as lazy dependencies for use in Zig projects.

## Usage

Add this package to your `build.zig.zon`:

```bash
zig fetch --save=godot git+https://github.com/gdzig/godot-binaries
```

Then in your `build.zig`:

```zig
const std = @import("std");
const godot = @import("godot");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    if (godot.executable(b, target, "~4.5")) |exe_path| {
        // exe_path is a LazyPath to the Godot binary
    }
}
```

## Version Constraints

| Constraint  | Meaning                 | Example Match               |
| ----------- | ----------------------- | --------------------------- |
| `"4.5.1"`   | Exact version           | 4.5.1 only                  |
| `"~4.5"`    | Any patch version       | 4.5.0, 4.5.1, ... (highest) |
| `"^4"`      | Any minor/patch version | 4.0.0, 4.5.1, ... (highest) |
| `">=4.0.0"` | Version or higher       | 4.0.0+ (highest)            |
| `"latest"`  | Latest available        | 4.5.1 (currently)           |

## Supported Platforms

| Platform | Architectures             |
| -------- | ------------------------- |
| Linux    | x86_64, x86, aarch64, arm |
| macOS    | universal                 |
| Windows  | x86_64, x86, aarch64      |

## API

### `executable(b, target, constraint) -> ?LazyPath`

Returns a `LazyPath` to the Godot executable matching the version constraint for the given target. Returns `null` if no match or not yet fetched.

### `dependency(b, target, constraint) -> ?*Dependency`

Returns the raw dependency if you need access to other files in the package.

## Syncing

The repository syncs automatically:

- Nightly at 3am UTC
- On manual workflow dispatch
- Via `repository_dispatch` webhook

To sync manually:

```sh
./sync.sh
```

## License

Godot Engine is licensed under the MIT license.
See https://github.com/godotengine/godot/blob/master/LICENSE.txt

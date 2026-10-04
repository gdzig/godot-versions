//! Build-time helper used by `build.zig`.
//!
//! Zig 0.17 no longer supports custom build steps, so the logic that used to
//! live in `FetchStep.zig` and `HeadersStep.zig` runs as a host executable
//! driven by `std.Build.Step.Run`.
//!
//! Usage:
//!   godot_tool fetch <zig_exe> <global_cache_dir> <url> <hash> <exe_name> <out_dir>
//!   godot_tool headers <godot_exe> <out_dir> <auto|docs|nodocs> <auto|json|nojson>

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) usage();
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "fetch")) {
        if (args.len != 8) usage();
        try fetch(arena, io, init.environ_map, .{
            .zig_exe = args[2],
            .global_cache_dir = args[3],
            .url = args[4],
            .expected_hash = args[5],
            .exe_name = args[6],
            .out_dir = args[7],
        });
    } else if (std.mem.eql(u8, cmd, "headers")) {
        if (args.len != 6) usage();
        try headers(arena, io, args[2], args[3], args[4], args[5]);
    } else usage();
}

fn usage() noreturn {
    std.process.fatal(
        \\usage:
        \\  godot_tool fetch <zig_exe> <global_cache_dir> <url> <hash> <exe_name> <out_dir>
        \\  godot_tool headers <godot_exe> <out_dir> <auto|docs|nodocs> <auto|json|nojson>
    , .{});
}

// ============================================================================
// fetch
// ============================================================================

const FetchOptions = struct {
    zig_exe: []const u8,
    global_cache_dir: []const u8,
    url: []const u8,
    expected_hash: []const u8,
    /// Fixed path (relative to out_dir) where the Godot executable must end up.
    exe_name: []const u8,
    out_dir: []const u8,
};

fn fetch(arena: std.mem.Allocator, io: Io, environ_map: *std.process.Environ.Map, opts: FetchOptions) !void {
    // Use `zig fetch` to download the archive: it has TLS support and stores
    // the package as a tarball in the global cache.
    var env = try environ_map.clone(arena);
    try env.put("ZIG_GLOBAL_CACHE_DIR", opts.global_cache_dir);

    const result = try std.process.run(arena, io, .{
        .argv = &.{ opts.zig_exe, "fetch", opts.url },
        .environ_map = &env,
    });
    if (!result.term.success()) {
        std.process.fatal("'zig fetch {s}' failed:\n{s}", .{ opts.url, result.stderr });
    }

    const pkg_hash = std.mem.trim(u8, result.stdout, "\n\r ");
    if (!std.mem.eql(u8, pkg_hash, opts.expected_hash)) {
        std.process.fatal("hash mismatch for '{s}': expected '{s}', got '{s}'", .{ opts.url, opts.expected_hash, pkg_hash });
    }

    // Extract <global_cache>/p/<hash>.tar.gz into the output directory.
    const tarball_path = try Dir.path.join(arena, &.{ opts.global_cache_dir, "p", try std.fmt.allocPrint(arena, "{s}.tar.gz", .{pkg_hash}) });
    const tarball = Dir.cwd().openFile(io, tarball_path, .{}) catch |err| {
        std.process.fatal("unable to open fetched package '{s}': {t}", .{ tarball_path, err });
    };
    defer tarball.close(io);

    var out_dir = try Dir.cwd().createDirPathOpen(io, opts.out_dir, .{ .open_options = .{ .iterate = true } });
    defer out_dir.close(io);

    var file_buf: [64 * 1024]u8 = undefined;
    var file_reader = tarball.reader(io, &file_buf);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&file_reader.interface, .gzip, &window);
    // Tarballs created by `zig fetch` have a single top-level directory named after the hash.
    std.tar.extract(io, out_dir, &decompress.reader, .{ .strip_components = 1 }) catch |err| {
        std.process.fatal("failed to extract '{s}': {t}", .{ tarball_path, err });
    };

    try placeExecutable(arena, io, out_dir, opts.exe_name);
}

/// Ensure the Godot executable is available at `exe_name` within `dir`.
fn placeExecutable(arena: std.mem.Allocator, io: Io, dir: Dir, exe_name: []const u8) !void {
    const macos_bundle_exe = "Godot.app/Contents/MacOS/Godot";
    if (std.mem.eql(u8, exe_name, macos_bundle_exe)) {
        // `zig fetch` strips the single top-level `Godot.app` directory,
        // leaving `Contents/`. Restore the bundle layout.
        if (dir.access(io, "Contents", .{})) |_| {
            try dir.createDirPath(io, "Godot.app");
            try dir.rename("Contents", dir, "Godot.app/Contents", io);
        } else |_| {}
        dir.access(io, macos_bundle_exe, .{}) catch
            std.process.fatal("could not find '{s}' in extracted archive", .{macos_bundle_exe});
        try dir.setFilePermissions(io, macos_bundle_exe, .executable_file, .{});
        return;
    }

    const found = try findGodotExecutable(arena, io, dir);
    if (!std.mem.eql(u8, found, exe_name)) {
        dir.hardLink(found, dir, exe_name, io, .{}) catch {
            try dir.copyFile(found, dir, exe_name, io, .{});
        };
    }
    if (@import("builtin").os.tag != .windows) {
        try dir.setFilePermissions(io, exe_name, .executable_file, .{});
    }
}

fn findGodotExecutable(arena: std.mem.Allocator, io: Io, dir: Dir) ![]const u8 {
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        // Match Godot executable: Godot_v* or Godot.* (but skip console versions)
        if (std.mem.startsWith(u8, name, "Godot_v") or std.mem.startsWith(u8, name, "Godot.")) {
            if (std.mem.indexOf(u8, name, "_console") != null) continue;
            return arena.dupe(u8, name);
        }
    }
    std.process.fatal("could not find Godot executable in extracted archive", .{});
}

// ============================================================================
// headers
// ============================================================================

fn headers(
    arena: std.mem.Allocator,
    io: Io,
    godot_exe_arg: []const u8,
    out_dir_path: []const u8,
    docs_mode: []const u8,
    json_mode: []const u8,
) !void {
    // Godot dumps into its cwd, so the executable path must be absolute.
    const godot_exe = Dir.cwd().realPathFileAlloc(io, godot_exe_arg, arena) catch |err| {
        std.process.fatal("unable to resolve Godot executable '{s}': {t}", .{ godot_exe_arg, err });
    };

    var out_dir = try Dir.cwd().createDirPathOpen(io, out_dir_path, .{});
    defer out_dir.close(io);

    const need_version = std.mem.eql(u8, docs_mode, "auto") or std.mem.eql(u8, json_mode, "auto");
    const version: ?ParsedVersion = if (need_version)
        parseVersionString(try runGodotVersion(arena, io, godot_exe))
    else
        null;

    const use_docs = if (std.mem.eql(u8, docs_mode, "auto")) shouldUseDocs(version.?) else std.mem.eql(u8, docs_mode, "docs");
    const has_json = if (std.mem.eql(u8, json_mode, "auto")) hasJsonInterface(version.?) else std.mem.eql(u8, json_mode, "json");

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, godot_exe);
    try argv.append(arena, if (use_docs) "--dump-extension-api-with-docs" else "--dump-extension-api");
    try argv.append(arena, "--dump-gdextension-interface");
    if (has_json) try argv.append(arena, "--dump-gdextension-interface-json");
    try argv.append(arena, "--headless");
    try argv.append(arena, "--quit");

    const result = try std.process.run(arena, io, .{
        .argv = argv.items,
        .cwd = .{ .dir = out_dir },
    });
    if (!result.term.success()) {
        std.process.fatal("Godot exited with non-zero status:\n{s}", .{result.stderr});
    }
}

fn runGodotVersion(arena: std.mem.Allocator, io: Io, godot_exe: []const u8) ![]const u8 {
    const result = try std.process.run(arena, io, .{
        .argv = &.{ godot_exe, "--version" },
        .stdout_limit = .limited(4096),
    });
    if (!result.term.success()) {
        std.process.fatal("Godot --version exited with non-zero status:\n{s}", .{result.stderr});
    }
    const first_line = std.mem.sliceTo(result.stdout, '\n');
    return std.mem.trim(u8, first_line, "\r ");
}

/// Parsed version info for determining flags
const ParsedVersion = struct {
    major: u8,
    minor: u8,
    patch: u8,
    prerelease: ?[]const u8,
};

/// Parse version string like "4.6.beta2.official.abc123"
fn parseVersionString(version_str: []const u8) ParsedVersion {
    var result: ParsedVersion = .{ .major = 4, .minor = 0, .patch = 0, .prerelease = null };
    var parts = std.mem.splitScalar(u8, version_str, '.');

    if (parts.next()) |major_str| result.major = std.fmt.parseInt(u8, major_str, 10) catch 4;
    if (parts.next()) |minor_str| result.minor = std.fmt.parseInt(u8, minor_str, 10) catch 0;

    // Parse patch or prerelease
    if (parts.next()) |third| {
        if (std.fmt.parseInt(u8, third, 10)) |patch| {
            result.patch = patch;
            if (parts.next()) |pre| result.prerelease = pre;
        } else |_| {
            result.prerelease = third;
        }
    }
    return result;
}

/// Check if this version should use --dump-extension-api-with-docs
fn shouldUseDocs(version: ParsedVersion) bool {
    // 4.1.x: no docs
    if (version.major == 4 and version.minor == 1) return false;

    // 4.2.0-dev[1-5]: no docs
    if (version.major == 4 and version.minor == 2 and version.patch == 0) {
        if (version.prerelease) |pre| {
            if (std.mem.startsWith(u8, pre, "dev")) {
                const num = std.fmt.parseInt(u8, pre[3..], 10) catch return true;
                return num >= 6;
            }
        }
    }

    // Everything else 4.2+ has docs
    return version.major > 4 or (version.major == 4 and version.minor >= 2);
}

/// Check if this version has --dump-gdextension-interface-json
fn hasJsonInterface(version: ParsedVersion) bool {
    // Only 4.6.0-dev5 and later
    if (version.major != 4) return version.major > 4;
    if (version.minor != 6) return version.minor > 6;

    if (version.prerelease) |pre| {
        if (std.mem.startsWith(u8, pre, "dev")) {
            const num = std.fmt.parseInt(u8, pre[3..], 10) catch return true;
            return num >= 5;
        }
        if (std.mem.startsWith(u8, pre, "beta") or
            std.mem.startsWith(u8, pre, "rc") or
            std.mem.startsWith(u8, pre, "stable"))
        {
            return true;
        }
    }

    // If patch > 0, it's post-4.6.0 so it has JSON interface
    return version.patch > 0;
}

test parseVersionString {
    const v = parseVersionString("4.6.beta2.official.abc123");
    try std.testing.expectEqual(@as(u8, 4), v.major);
    try std.testing.expectEqual(@as(u8, 6), v.minor);
    try std.testing.expectEqualStrings("beta2", v.prerelease.?);
    try std.testing.expect(hasJsonInterface(v));
    try std.testing.expect(!hasJsonInterface(parseVersionString("4.5.1.stable.official")));
    try std.testing.expect(!shouldUseDocs(parseVersionString("4.1.3.stable.official")));
}

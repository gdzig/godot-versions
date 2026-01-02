//! A build step that dumps GDExtension headers from a Godot executable.
//! Can use a known version or detect it at build time.

const std = @import("std");
const Step = std.Build.Step;
const fs = std.fs;
const build_zig = @import("build.zig");

const HeadersStep = @This();

step: Step,
godot_exe: std.Build.LazyPath,
generated_directory: std.Build.GeneratedFile,
/// If set, use these flags directly. If null, detect version at build time.
known_flags: ?Flags,

const Flags = struct {
    use_docs: bool,
    has_json: bool,
};

pub const base_id: Step.Id = .custom;

/// Create a HeadersStep that detects version at build time
pub fn create(owner: *std.Build, godot_exe: std.Build.LazyPath) *HeadersStep {
    return createWithFlags(owner, godot_exe, null);
}

/// Create a HeadersStep with known version flags
pub fn createWithFlags(owner: *std.Build, godot_exe: std.Build.LazyPath, flags: ?Flags) *HeadersStep {
    const headers = owner.allocator.create(HeadersStep) catch @panic("OOM");
    headers.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "dump gdextension headers",
            .owner = owner,
            .makeFn = make,
        }),
        .godot_exe = godot_exe.dupe(owner),
        .generated_directory = .{ .step = &headers.step },
        .known_flags = flags,
    };
    godot_exe.addStepDependencies(&headers.step);
    return headers;
}

pub fn getDirectory(headers: *HeadersStep) std.Build.LazyPath {
    return .{ .generated = .{ .file = &headers.generated_directory } };
}

fn make(step: *Step, prog_node: Step.MakeOptions) !void {
    const b = step.owner;
    const arena = b.allocator;
    const headers: *HeadersStep = @fieldParentPtr("step", step);

    // Get the godot executable path (make absolute since we change cwd)
    const godot_path_rel = headers.godot_exe.getPath2(b, step);
    const godot_path = std.fs.cwd().realpathAlloc(arena, godot_path_rel) catch |err| {
        return step.fail("failed to resolve Godot path '{s}': {s}", .{ godot_path_rel, @errorName(err) });
    };

    // Set up caching based on godot executable path
    // We hash the path string - if the executable changes, the path will be different
    // (e.g., different cache directory for different builds)
    var man = b.graph.cache.obtain();
    defer man.deinit();

    man.hash.addBytes(godot_path);

    // Check cache
    if (try step.cacheHitAndWatch(&man)) {
        const digest = man.final();
        headers.generated_directory.path = try b.cache_root.join(arena, &.{ "o", &digest });
        step.result_cached = true;
        return;
    }

    const digest = man.final();
    const cache_path = "o" ++ fs.path.sep_str ++ digest;

    // Create output directory
    var cache_dir = b.cache_root.handle.makeOpenPath(cache_path, .{}) catch |err| {
        return step.fail("unable to make cache path '{s}': {s}", .{
            cache_path, @errorName(err),
        });
    };
    defer cache_dir.close();

    headers.generated_directory.path = try b.cache_root.join(arena, &.{ "o", &digest });

    // Determine flags - use known flags or detect from version
    const use_docs, const has_json = if (headers.known_flags) |flags|
        .{ flags.use_docs, flags.has_json }
    else blk: {
        const version_str = runGodotVersion(step, godot_path, prog_node) catch |err| {
            return step.fail("failed to get Godot version: {s}", .{@errorName(err)});
        };
        const version = parseVersionString(version_str);
        break :blk .{ shouldUseDocs(version), hasJsonInterface(version) };
    };

    // Build arguments array (max 6 args)
    var args: [6][]const u8 = undefined;
    var arg_count: usize = 0;

    args[arg_count] = godot_path;
    arg_count += 1;

    args[arg_count] = if (use_docs) "--dump-extension-api-with-docs" else "--dump-extension-api";
    arg_count += 1;

    args[arg_count] = "--dump-gdextension-interface";
    arg_count += 1;

    if (has_json) {
        args[arg_count] = "--dump-gdextension-interface-json";
        arg_count += 1;
    }

    args[arg_count] = "--headless";
    arg_count += 1;

    args[arg_count] = "--quit";
    arg_count += 1;

    // Run godot to dump headers
    const cwd_path = headers.generated_directory.path orelse
        return step.fail("generated directory path not set", .{});
    var child = std.process.Child.init(args[0..arg_count], arena);
    child.cwd = cwd_path;
    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;

    child.spawn() catch |err| {
        return step.fail("failed to spawn Godot: {s}", .{@errorName(err)});
    };

    const result = child.wait() catch |err| {
        return step.fail("failed to wait for Godot: {s}", .{@errorName(err)});
    };

    // Godot returns 0 on success
    if (result.Exited != 0) {
        return step.fail("Godot exited with code {d}", .{result.Exited});
    }

    // Write the manifest to finalize the cache entry
    try man.writeManifest();
}

fn runGodotVersion(step: *Step, godot_path: []const u8, prog_node: Step.MakeOptions) ![]const u8 {
    _ = prog_node;
    const arena = step.owner.allocator;

    var child = std.process.Child.init(&.{ godot_path, "--version" }, arena);
    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Pipe;

    child.spawn() catch |err| {
        return step.fail("failed to spawn Godot --version: {s}", .{@errorName(err)});
    };

    const stdout = child.stdout.?.readToEndAlloc(arena, 1024) catch |err| {
        return step.fail("failed to read Godot version output: {s}", .{@errorName(err)});
    };

    const result = child.wait() catch |err| {
        return step.fail("failed to wait for Godot --version: {s}", .{@errorName(err)});
    };

    if (result.Exited != 0) {
        return step.fail("Godot --version exited with code {d}", .{result.Exited});
    }

    // Return first line, trimmed
    const first_line = std.mem.sliceTo(stdout, '\n');
    return std.mem.trimRight(u8, first_line, "\r ");
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
    var result: ParsedVersion = .{
        .major = 4,
        .minor = 0,
        .patch = 0,
        .prerelease = null,
    };

    var parts = std.mem.splitScalar(u8, version_str, '.');

    // Parse major
    if (parts.next()) |major_str| {
        result.major = std.fmt.parseInt(u8, major_str, 10) catch 4;
    }

    // Parse minor
    if (parts.next()) |minor_str| {
        result.minor = std.fmt.parseInt(u8, minor_str, 10) catch 0;
    }

    // Parse patch or prerelease
    if (parts.next()) |third| {
        // Could be patch number or prerelease (e.g., "0" or "beta2")
        if (std.fmt.parseInt(u8, third, 10)) |patch| {
            result.patch = patch;
            // Next part would be prerelease
            if (parts.next()) |pre| {
                result.prerelease = pre;
            }
        } else |_| {
            // Not a number, it's a prerelease
            result.prerelease = third;
            result.patch = 0;
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
    if (version.major > 4) return true;
    if (version.major < 4) return false;

    // major == 4
    if (version.minor > 6) return true;
    if (version.minor < 6) return false;

    // major == 4, minor == 6
    if (version.prerelease) |pre| {
        if (std.mem.startsWith(u8, pre, "dev")) {
            const num = std.fmt.parseInt(u8, pre[3..], 10) catch return true;
            return num >= 5;
        }
        // beta, rc, stable all have it
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

const std = @import("std");
const root = @import("root");

pub fn build(b: *std.Build) void {
    if (@hasDecl(root, "root") and root.root != @This()) return;

    const target = b.standardTargetOptions(.{});
    const version = b.option([]const u8, "version", "Godot version constraint (default: latest)") orelse "latest";

    if (executable(b, target, version)) |exe_path| {
        const install = b.addInstallBinFile(exe_path, "godot");
        b.getInstallStep().dependOn(&install.step);

        const run = std.Build.Step.Run.create(b, "run godot");
        run.addFileArg(exe_path);
        if (b.args) |args| run.addArgs(args);
        run.stdio = .inherit;

        const run_step = b.step("run", "Run Godot");
        run_step.dependOn(&run.step);
    }
}

pub const Version = struct {
    major: u8,
    minor: u8,
    patch: u8,

    pub fn parse(str: []const u8) ?Version {
        var it = std.mem.splitScalar(u8, str, '_');
        const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const minor = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const patch = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        return .{ .major = major, .minor = minor, .patch = patch };
    }

    pub fn order(self: Version, other: Version) std.math.Order {
        if (self.major != other.major) return std.math.order(self.major, other.major);
        if (self.minor != other.minor) return std.math.order(self.minor, other.minor);
        return std.math.order(self.patch, other.patch);
    }
};

pub const Constraint = union(enum) {
    exact: Version,
    /// ~1.2 matches 1.2.x (any patch)
    tilde: struct { major: u8, minor: u8 },
    /// ^1 matches 1.x.x (any minor/patch, same major)
    caret: struct { major: u8 },
    /// >=1.2.3
    gte: Version,
    /// Latest available
    latest,

    pub fn parse(str: []const u8) ?Constraint {
        if (std.mem.eql(u8, str, "latest")) return .latest;

        if (str.len > 0 and str[0] == '~') {
            var it = std.mem.splitScalar(u8, str[1..], '.');
            const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            const minor = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            return .{ .tilde = .{ .major = major, .minor = minor } };
        }

        if (str.len > 0 and str[0] == '^') {
            const major = std.fmt.parseInt(u8, str[1..], 10) catch return null;
            return .{ .caret = .{ .major = major } };
        }

        if (str.len >= 2 and str[0] == '>' and str[1] == '=') {
            var it = std.mem.splitScalar(u8, str[2..], '.');
            const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            const minor = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            const patch = std.fmt.parseInt(u8, it.next() orelse "0", 10) catch return null;
            return .{ .gte = .{ .major = major, .minor = minor, .patch = patch } };
        }

        // Version: "4" means ^4 (any 4.x.x), "4.2" means ~4.2 (any 4.2.x), "4.2.1" means exact
        var it = std.mem.splitScalar(u8, str, '.');
        const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const minor_str = it.next();
        if (minor_str == null) {
            // No minor specified (e.g., "4") - treat as caret (any 4.x.x)
            return .{ .caret = .{ .major = major } };
        }
        const minor = std.fmt.parseInt(u8, minor_str.?, 10) catch return null;
        const patch_str = it.next();
        if (patch_str == null) {
            // No patch specified (e.g., "4.2") - treat as tilde (any 4.2.x)
            return .{ .tilde = .{ .major = major, .minor = minor } };
        }
        const patch = std.fmt.parseInt(u8, patch_str.?, 10) catch return null;
        return .{ .exact = .{ .major = major, .minor = minor, .patch = patch } };
    }

    pub fn matches(self: Constraint, version: Version) bool {
        return switch (self) {
            .exact => |v| version.major == v.major and version.minor == v.minor and version.patch == v.patch,
            .tilde => |t| version.major == t.major and version.minor == t.minor,
            .caret => |c| version.major == c.major,
            .gte => |v| version.order(v) != .lt,
            .latest => true,
        };
    }
};

const Platform = enum { linux, macos, windows };
const Arch = enum { x86_64, x86, aarch64, arm, universal };

fn targetToPlatformArch(target: std.Target) struct { platform: Platform, arch: Arch } {
    const platform: Platform = switch (target.os.tag) {
        .linux => .linux,
        .macos => .macos,
        .windows => .windows,
        else => @panic("Unsupported platform for Godot"),
    };

    const arch: Arch = switch (target.os.tag) {
        .macos => .universal,
        else => switch (target.cpu.arch) {
            .x86_64 => .x86_64,
            .x86 => .x86,
            .aarch64 => .aarch64,
            .arm => .arm,
            else => @panic("Unsupported architecture for Godot"),
        },
    };

    return .{ .platform = platform, .arch = arch };
}

fn platformToString(platform: Platform) []const u8 {
    return switch (platform) {
        .linux => "linux",
        .macos => "macos",
        .windows => "windows",
    };
}

fn archToString(arch: Arch) []const u8 {
    return switch (arch) {
        .x86_64 => "x86_64",
        .x86 => "x86",
        .aarch64 => "aarch64",
        .arm => "arm",
        .universal => "universal",
    };
}

/// Parse a dependency name like "godot_4_5_1_linux_x86_64" into version and platform/arch
fn parseDependencyName(name: []const u8) ?struct { version: Version, platform: []const u8, arch: []const u8 } {
    // Must start with "godot_"
    const prefix = "godot_";
    if (!std.mem.startsWith(u8, name, prefix)) return null;

    const rest = name[prefix.len..];

    // Find version (first 3 underscore-separated numbers)
    var it = std.mem.splitScalar(u8, rest, '_');
    const major_str = it.next() orelse return null;
    const minor_str = it.next() orelse return null;
    const patch_str = it.next() orelse return null;
    const platform = it.next() orelse return null;
    // Arch is the rest of the string (may contain underscores like x86_64)
    const arch = it.rest();
    if (arch.len == 0) return null;

    const major = std.fmt.parseInt(u8, major_str, 10) catch return null;
    const minor = std.fmt.parseInt(u8, minor_str, 10) catch return null;
    const patch = std.fmt.parseInt(u8, patch_str, 10) catch return null;

    return .{
        .version = .{ .major = major, .minor = minor, .patch = patch },
        .platform = platform,
        .arch = arch,
    };
}

/// Find the Godot executable in the dependency directory
fn findExecutable(dep: *std.Build.Dependency) ?std.Build.LazyPath {
    const root_path = dep.builder.build_root.path orelse return null;
    var dir = std.fs.openDirAbsolute(root_path, .{ .iterate = true }) catch return null;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch return null) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.startsWith(u8, entry.name, "Godot_v") or std.mem.startsWith(u8, entry.name, "Godot.")) {
            // Skip console executables on Windows
            if (std.mem.indexOf(u8, entry.name, "_console") != null) continue;
            // Dupe the name since entry.name is a temporary buffer
            const name = dep.builder.allocator.dupe(u8, entry.name) catch return null;
            return dep.path(name);
        }
    }
    return null;
}

fn findMatchingDependency(
    available_deps: []const struct { []const u8, []const u8 },
    constraint: Constraint,
    platform_str: []const u8,
    arch_str: []const u8,
) []const u8 {
    var best_name: ?[]const u8 = null;
    var best_version: ?Version = null;

    for (available_deps) |dep| {
        const name = dep[0];
        const parsed = parseDependencyName(name) orelse continue;

        // Check platform/arch match
        if (!std.mem.eql(u8, parsed.platform, platform_str)) continue;
        if (!std.mem.eql(u8, parsed.arch, arch_str)) continue;

        // Check version constraint
        if (!constraint.matches(parsed.version)) continue;

        // Keep the highest matching version
        if (best_version == null or parsed.version.order(best_version.?) == .gt) {
            best_version = parsed.version;
            best_name = name;
        }
    }

    return best_name orelse @panic("No Godot version found matching constraint for this platform/architecture");
}

fn findMatchingHeadersVersion(
    available_deps: []const struct { []const u8, []const u8 },
    constraint: Constraint,
) Version {
    var best_version: ?Version = null;

    for (available_deps) |dep| {
        const name = dep[0];
        const parsed = parseDependencyName(name) orelse continue;

        // Check version constraint
        if (!constraint.matches(parsed.version)) continue;

        // Keep the highest matching version
        if (best_version == null or parsed.version.order(best_version.?) == .gt) {
            best_version = parsed.version;
        }
    }

    return best_version orelse @panic("No Godot version found matching constraint");
}

fn getSelfDependency(b: *std.Build) *std.Build.Dependency {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;
    const build_zig = @This();

    // Check if this build.zig is a dependency in the root project
    inline for (@typeInfo(deps.packages).@"struct".decls) |decl| {
        const pkg_hash = decl.name;
        const pkg = @field(deps.packages, pkg_hash);
        if (@hasDecl(pkg, "build_zig") and pkg.build_zig == build_zig) {
            // We're a dependency - find our name from available_deps
            for (b.available_deps) |dep| {
                if (std.mem.eql(u8, dep[1], pkg_hash)) {
                    return b.dependency(dep[0], .{});
                }
            }
        }
    }

    @panic("Could not find self as dependency");
}

/// Get a Godot executable path matching the version constraint for the given target.
///
/// Constraint syntax:
///   - "4.5.1"   - exact version
///   - "~4.5"    - any 4.5.x patch version (highest patch)
///   - "^4"      - any 4.x.x version (highest minor/patch)
///   - ">=4.0.0" - version 4.0.0 or higher (highest available)
///   - "latest"  - latest available version
///
/// Returns null only while waiting for the lazy dependency to be fetched.
/// Panics if no matching version exists or the platform is unsupported.
///
/// Example:
///   const godot = @import("godot");
///   if (godot.executable(b, target, "~4.5")) |exe_path| {
///       // exe_path is a LazyPath to the Godot executable
///   }
pub fn executable(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    constraint_str: []const u8,
) ?std.Build.LazyPath {
    const dep = dependency(b, target, constraint_str) orelse return null;

    return findExecutable(dep);
}

/// Get the headers (extension_api.json and gdextension_interface.h) for a Godot version.
///
/// This does not require downloading the Godot executable - headers are vendored
/// in this package.
///
/// Panics if no matching version exists.
pub fn headers(
    b: *std.Build,
    constraint_str: []const u8,
) std.Build.LazyPath {
    const constraint = Constraint.parse(constraint_str) orelse
        @panic("Invalid version constraint");

    const godot_builder = getGodotBuilder(b);
    const version = findMatchingHeadersVersion(godot_builder.available_deps, constraint);
    const sub_path = b.fmt("vendor/godot_{d}_{d}_{d}", .{ version.major, version.minor, version.patch });

    return .{
        .dependency = .{
            .dependency = getSelfDependency(b),
            .sub_path = sub_path,
        },
    };
}

/// Get the dependency for a Godot version (if you need access to other files).
/// Most users should use `executable()` or `headers()` instead.
///
/// Returns null only while waiting for the lazy dependency to be fetched.
/// Panics if no matching version exists or the platform is unsupported.
pub fn dependency(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    constraint_str: []const u8,
) ?*std.Build.Dependency {
    const constraint = Constraint.parse(constraint_str) orelse
        @panic("Invalid version constraint");

    const plat = targetToPlatformArch(target.result);
    const platform_str = platformToString(plat.platform);
    const arch_str = archToString(plat.arch);

    // Get the godot package's builder - either ourselves (if root) or via dependencyFromBuildZig
    const godot_builder = getGodotBuilder(b);
    const name = findMatchingDependency(godot_builder.available_deps, constraint, platform_str, arch_str);
    return godot_builder.lazyDependency(name, .{});
}

fn getGodotBuilder(b: *std.Build) *std.Build {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;
    const build_zig = @This();

    // Check if this build.zig is a dependency in the root project
    inline for (@typeInfo(deps.packages).@"struct".decls) |decl| {
        const pkg_hash = decl.name;
        const pkg = @field(deps.packages, pkg_hash);
        if (@hasDecl(pkg, "build_zig") and pkg.build_zig == build_zig) {
            // We're a dependency - find our name from available_deps and use dependency()
            for (b.available_deps) |dep| {
                if (std.mem.eql(u8, dep[1], pkg_hash)) {
                    return b.dependency(dep[0], .{}).builder;
                }
            }
        }
    }

    // We're the root package
    return b;
}

test "Version.parse" {
    const v = Version.parse("4_5_1").?;
    try std.testing.expectEqual(@as(u8, 4), v.major);
    try std.testing.expectEqual(@as(u8, 5), v.minor);
    try std.testing.expectEqual(@as(u8, 1), v.patch);
}

test "Version.order" {
    const v1 = Version{ .major = 4, .minor = 5, .patch = 1 };
    const v2 = Version{ .major = 4, .minor = 5, .patch = 0 };
    const v3 = Version{ .major = 4, .minor = 4, .patch = 9 };
    const v4 = Version{ .major = 3, .minor = 9, .patch = 9 };

    try std.testing.expectEqual(std.math.Order.gt, v1.order(v2));
    try std.testing.expectEqual(std.math.Order.gt, v1.order(v3));
    try std.testing.expectEqual(std.math.Order.gt, v1.order(v4));
    try std.testing.expectEqual(std.math.Order.eq, v1.order(v1));
}

test "Constraint.parse exact" {
    const c = Constraint.parse("4.5.1").?;
    try std.testing.expectEqual(Constraint{ .exact = .{ .major = 4, .minor = 5, .patch = 1 } }, c);
}

test "Constraint.parse implicit tilde" {
    // "4.5" without patch becomes ~4.5 (any 4.5.x)
    const c = Constraint.parse("4.5").?;
    try std.testing.expectEqual(Constraint{ .tilde = .{ .major = 4, .minor = 5 } }, c);
}

test "Constraint.parse implicit caret" {
    // "4" without minor becomes ^4 (any 4.x.x)
    const c = Constraint.parse("4").?;
    try std.testing.expectEqual(Constraint{ .caret = .{ .major = 4 } }, c);
}

test "Constraint.parse tilde" {
    const c = Constraint.parse("~4.5").?;
    try std.testing.expectEqual(Constraint{ .tilde = .{ .major = 4, .minor = 5 } }, c);
}

test "Constraint.parse caret" {
    const c = Constraint.parse("^4").?;
    try std.testing.expectEqual(Constraint{ .caret = .{ .major = 4 } }, c);
}

test "Constraint.parse gte" {
    const c = Constraint.parse(">=4.0.0").?;
    try std.testing.expectEqual(Constraint{ .gte = .{ .major = 4, .minor = 0, .patch = 0 } }, c);
}

test "Constraint.parse latest" {
    const c = Constraint.parse("latest").?;
    try std.testing.expectEqual(Constraint.latest, c);
}

test "Constraint.matches exact" {
    const c = Constraint.parse("4.5.1").?;
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1 }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0 }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 4, .patch = 1 }));
}

test "Constraint.matches tilde" {
    const c = Constraint.parse("~4.5").?;
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0 }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1 }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 99 }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 4, .patch = 0 }));
    try std.testing.expect(!c.matches(.{ .major = 3, .minor = 5, .patch = 0 }));
}

test "Constraint.matches caret" {
    const c = Constraint.parse("^4").?;
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 0, .patch = 0 }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1 }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 99, .patch = 99 }));
    try std.testing.expect(!c.matches(.{ .major = 3, .minor = 0, .patch = 0 }));
    try std.testing.expect(!c.matches(.{ .major = 5, .minor = 0, .patch = 0 }));
}

test "Constraint.matches gte" {
    const c = Constraint.parse(">=4.0.0").?;
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 0, .patch = 0 }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1 }));
    try std.testing.expect(c.matches(.{ .major = 5, .minor = 0, .patch = 0 }));
    try std.testing.expect(!c.matches(.{ .major = 3, .minor = 9, .patch = 9 }));
}

test "Constraint.matches latest" {
    const c = Constraint.parse("latest").?;
    try std.testing.expect(c.matches(.{ .major = 1, .minor = 0, .patch = 0 }));
    try std.testing.expect(c.matches(.{ .major = 99, .minor = 99, .patch = 99 }));
}

test "parseDependencyName" {
    const parsed = parseDependencyName("godot_4_5_1_linux_x86_64").?;
    try std.testing.expectEqual(@as(u8, 4), parsed.version.major);
    try std.testing.expectEqual(@as(u8, 5), parsed.version.minor);
    try std.testing.expectEqual(@as(u8, 1), parsed.version.patch);
    try std.testing.expectEqualStrings("linux", parsed.platform);
    try std.testing.expectEqualStrings("x86_64", parsed.arch);
}

test "parseDependencyName invalid" {
    try std.testing.expect(parseDependencyName("not_godot") == null);
    try std.testing.expect(parseDependencyName("godot_invalid") == null);
}

test "findMatchingDependency" {
    const deps = [_]struct { []const u8, []const u8 }{
        .{ "godot_4_5_1_linux_x86_64", "hash1" },
        .{ "godot_4_5_0_linux_x86_64", "hash2" },
        .{ "godot_4_4_0_linux_x86_64", "hash3" },
        .{ "godot_3_6_0_linux_x86_64", "hash4" },
        .{ "godot_4_5_1_windows_x86_64", "hash5" },
    };

    // Exact match
    const exact = findMatchingDependency(&deps, Constraint.parse("4.5.1").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_linux_x86_64", exact);

    // Tilde gets highest patch
    const tilde = findMatchingDependency(&deps, Constraint.parse("~4.5").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_linux_x86_64", tilde);

    // Caret gets highest minor/patch
    const caret = findMatchingDependency(&deps, Constraint.parse("^4").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_linux_x86_64", caret);

    // Latest gets highest overall
    const latest = findMatchingDependency(&deps, Constraint.parse("latest").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_linux_x86_64", latest);

    // Different platform
    const win = findMatchingDependency(&deps, Constraint.parse("latest").?, "windows", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_windows_x86_64", win);
}

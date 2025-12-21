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

pub const Prerelease = union(enum) {
    dev: u8, // dev1, dev2, etc.
    beta: u8, // beta1, beta2, etc.
    rc: u8, // rc1, rc2, etc.
    stable, // no number

    pub fn parse(str: []const u8) ?Prerelease {
        if (std.mem.eql(u8, str, "stable")) return .stable;
        if (std.mem.startsWith(u8, str, "dev")) {
            const num = std.fmt.parseInt(u8, str[3..], 10) catch return null;
            return .{ .dev = num };
        }
        if (std.mem.startsWith(u8, str, "beta")) {
            const num = std.fmt.parseInt(u8, str[4..], 10) catch return null;
            return .{ .beta = num };
        }
        if (std.mem.startsWith(u8, str, "rc")) {
            const num = std.fmt.parseInt(u8, str[2..], 10) catch return null;
            return .{ .rc = num };
        }
        return null;
    }

    /// Returns the type ordering value (dev=0, beta=1, rc=2, stable=3)
    fn typeOrder(self: Prerelease) u8 {
        return switch (self) {
            .dev => 0,
            .beta => 1,
            .rc => 2,
            .stable => 3,
        };
    }

    /// Returns the number for numbered prereleases, or 0 for stable
    fn number(self: Prerelease) u8 {
        return switch (self) {
            .dev => |n| n,
            .beta => |n| n,
            .rc => |n| n,
            .stable => 0,
        };
    }

    pub fn order(self: Prerelease, other: Prerelease) std.math.Order {
        const self_type = self.typeOrder();
        const other_type = other.typeOrder();
        if (self_type != other_type) return std.math.order(self_type, other_type);
        // Same type, compare numbers
        return std.math.order(self.number(), other.number());
    }

    pub fn isStable(self: Prerelease) bool {
        return self == .stable;
    }
};

pub const Version = struct {
    major: u8,
    minor: u8,
    patch: u8,
    prerelease: Prerelease,

    /// Parse a version string like "4_5_1_stable" or "4_6_0_beta2"
    pub fn parse(str: []const u8) ?Version {
        var it = std.mem.splitScalar(u8, str, '_');
        const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const minor = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const patch = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const prerelease_str = it.next() orelse return null;
        const prerelease = Prerelease.parse(prerelease_str) orelse return null;
        return .{ .major = major, .minor = minor, .patch = patch, .prerelease = prerelease };
    }

    pub fn order(self: Version, other: Version) std.math.Order {
        if (self.major != other.major) return std.math.order(self.major, other.major);
        if (self.minor != other.minor) return std.math.order(self.minor, other.minor);
        if (self.patch != other.patch) return std.math.order(self.patch, other.patch);
        return self.prerelease.order(other.prerelease);
    }
};

/// Prerelease filter for constraints
pub const PrereleaseFilter = union(enum) {
    /// Only match stable releases (default)
    stable_only,
    /// Match a specific prerelease type (e.g., -beta matches any beta, -rc matches any rc)
    prerelease_type: enum { dev, beta, rc },
    /// Match an exact prerelease (e.g., -beta2, -rc1)
    exact_prerelease: Prerelease,
};

pub const Constraint = union(enum) {
    /// Exact version match (e.g., "4.5.1" or "4.5.1-beta2")
    exact: struct { major: u8, minor: u8, patch: u8, prerelease_filter: PrereleaseFilter },
    /// ~1.2 matches 1.2.x (any patch), stable only by default
    tilde: struct { major: u8, minor: u8, prerelease_filter: PrereleaseFilter },
    /// ^1 matches 1.x.x (any minor/patch, same major), stable only by default
    caret: struct { major: u8, prerelease_filter: PrereleaseFilter },
    /// >=1.2.3, stable only by default
    gte: struct { major: u8, minor: u8, patch: u8, prerelease_filter: PrereleaseFilter },
    /// Latest available (stable only by default)
    latest: PrereleaseFilter,

    /// Parse a prerelease filter from a string like "stable", "beta", "beta2", "rc", "rc1", "dev", "dev3"
    fn parsePrereleaseFilter(str: []const u8) ?PrereleaseFilter {
        if (std.mem.eql(u8, str, "stable")) return .stable_only;
        if (std.mem.eql(u8, str, "dev")) return .{ .prerelease_type = .dev };
        if (std.mem.eql(u8, str, "beta")) return .{ .prerelease_type = .beta };
        if (std.mem.eql(u8, str, "rc")) return .{ .prerelease_type = .rc };
        // Try parsing as exact prerelease (e.g., "beta2", "rc1", "dev3")
        if (Prerelease.parse(str)) |pre| {
            return .{ .exact_prerelease = pre };
        }
        return null;
    }

    pub fn parse(str: []const u8) ?Constraint {
        if (std.mem.eql(u8, str, "latest")) return .{ .latest = .stable_only };

        // Check for prerelease suffix (e.g., "-beta", "-rc1", "-stable")
        var prerelease_filter: PrereleaseFilter = .stable_only;
        var version_part = str;
        if (std.mem.lastIndexOfScalar(u8, str, '-')) |dash_idx| {
            const suffix = str[dash_idx + 1 ..];
            if (parsePrereleaseFilter(suffix)) |filter| {
                prerelease_filter = filter;
                version_part = str[0..dash_idx];
            }
        }

        if (std.mem.eql(u8, version_part, "latest")) return .{ .latest = prerelease_filter };

        if (version_part.len > 0 and version_part[0] == '~') {
            var it = std.mem.splitScalar(u8, version_part[1..], '.');
            const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            const minor = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            return .{ .tilde = .{ .major = major, .minor = minor, .prerelease_filter = prerelease_filter } };
        }

        if (version_part.len > 0 and version_part[0] == '^') {
            const major = std.fmt.parseInt(u8, version_part[1..], 10) catch return null;
            return .{ .caret = .{ .major = major, .prerelease_filter = prerelease_filter } };
        }

        if (version_part.len >= 2 and version_part[0] == '>' and version_part[1] == '=') {
            var it = std.mem.splitScalar(u8, version_part[2..], '.');
            const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            const minor = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
            const patch = std.fmt.parseInt(u8, it.next() orelse "0", 10) catch return null;
            return .{ .gte = .{ .major = major, .minor = minor, .patch = patch, .prerelease_filter = prerelease_filter } };
        }

        // Version: "4" means ^4 (any 4.x.x), "4.2" means ~4.2 (any 4.2.x), "4.2.1" means exact
        var it = std.mem.splitScalar(u8, version_part, '.');
        const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const minor_str = it.next();
        if (minor_str == null) {
            // No minor specified (e.g., "4") - treat as caret (any 4.x.x)
            return .{ .caret = .{ .major = major, .prerelease_filter = prerelease_filter } };
        }
        const minor = std.fmt.parseInt(u8, minor_str.?, 10) catch return null;
        const patch_str = it.next();
        if (patch_str == null) {
            // No patch specified (e.g., "4.2") - treat as tilde (any 4.2.x)
            return .{ .tilde = .{ .major = major, .minor = minor, .prerelease_filter = prerelease_filter } };
        }
        const patch = std.fmt.parseInt(u8, patch_str.?, 10) catch return null;
        return .{ .exact = .{ .major = major, .minor = minor, .patch = patch, .prerelease_filter = prerelease_filter } };
    }

    fn matchesPrerelease(filter: PrereleaseFilter, prerelease: Prerelease) bool {
        return switch (filter) {
            .stable_only => prerelease.isStable(),
            .prerelease_type => |pt| switch (pt) {
                .dev => switch (prerelease) {
                    .dev => true,
                    else => false,
                },
                .beta => switch (prerelease) {
                    .beta => true,
                    else => false,
                },
                .rc => switch (prerelease) {
                    .rc => true,
                    else => false,
                },
            },
            .exact_prerelease => |exact| std.meta.eql(prerelease, exact),
        };
    }

    pub fn matches(self: Constraint, version: Version) bool {
        const version_matches = switch (self) {
            .exact => |e| version.major == e.major and version.minor == e.minor and version.patch == e.patch,
            .tilde => |t| version.major == t.major and version.minor == t.minor,
            .caret => |c| version.major == c.major,
            .gte => |g| blk: {
                const base = Version{ .major = g.major, .minor = g.minor, .patch = g.patch, .prerelease = .stable };
                // For gte, we compare base versions (ignoring prerelease for the >= check)
                if (version.major != base.major) break :blk version.major > base.major;
                if (version.minor != base.minor) break :blk version.minor > base.minor;
                break :blk version.patch >= base.patch;
            },
            .latest => true,
        };

        if (!version_matches) return false;

        // Check prerelease filter
        const filter = switch (self) {
            .exact => |e| e.prerelease_filter,
            .tilde => |t| t.prerelease_filter,
            .caret => |c| c.prerelease_filter,
            .gte => |g| g.prerelease_filter,
            .latest => |f| f,
        };

        return matchesPrerelease(filter, version.prerelease);
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

/// Parse a dependency name like "godot_4_5_1_stable_linux_x86_64" or "godot_4_6_0_beta2_linux_x86_64"
fn parseDependencyName(name: []const u8) ?struct { version: Version, platform: []const u8, arch: []const u8 } {
    // Must start with "godot_"
    const prefix = "godot_";
    if (!std.mem.startsWith(u8, name, prefix)) return null;

    const rest = name[prefix.len..];

    // Find version (first 3 underscore-separated numbers, then prerelease, then platform, then arch)
    var it = std.mem.splitScalar(u8, rest, '_');
    const major_str = it.next() orelse return null;
    const minor_str = it.next() orelse return null;
    const patch_str = it.next() orelse return null;
    const prerelease_str = it.next() orelse return null;
    const platform = it.next() orelse return null;
    // Arch is the rest of the string (may contain underscores like x86_64)
    const arch = it.rest();
    if (arch.len == 0) return null;

    const major = std.fmt.parseInt(u8, major_str, 10) catch return null;
    const minor = std.fmt.parseInt(u8, minor_str, 10) catch return null;
    const patch = std.fmt.parseInt(u8, patch_str, 10) catch return null;
    const prerelease = Prerelease.parse(prerelease_str) orelse return null;

    return .{
        .version = .{ .major = major, .minor = minor, .patch = patch, .prerelease = prerelease },
        .platform = platform,
        .arch = arch,
    };
}

/// Find the Godot executable in the dependency directory
fn findExecutable(dep: *std.Build.Dependency) ?std.Build.LazyPath {
    var dir = dep.builder.build_root.handle.openDir(".", .{ .iterate = true }) catch return null;
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
    @setEvalBranchQuota(10000);
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
/// Constraint syntax (stable releases only by default):
///   - "4.5.1"       - exact stable version
///   - "~4.5"        - any 4.5.x stable patch version (highest patch)
///   - "^4"          - any 4.x.x stable version (highest minor/patch)
///   - ">=4.0.0"     - stable version 4.0.0 or higher (highest available)
///   - "latest"      - latest available stable version
///
/// Prerelease syntax (append -dev, -beta, -rc, or specific like -beta2):
///   - "4.6-beta"    - latest 4.6.x beta
///   - "4.6.0-beta2" - exact beta2 for 4.6.0
///   - "~4.6-rc"     - latest rc in 4.6.x range
///   - "latest-dev"  - latest dev build overall
///   - "^4-beta"     - latest beta in 4.x.x range
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
    const prerelease_str = switch (version.prerelease) {
        .dev => |n| b.fmt("dev{d}", .{n}),
        .beta => |n| b.fmt("beta{d}", .{n}),
        .rc => |n| b.fmt("rc{d}", .{n}),
        .stable => "stable",
    };
    const sub_path = b.fmt("vendor/godot_{d}_{d}_{d}_{s}", .{ version.major, version.minor, version.patch, prerelease_str });

    const dep = getSelfDependency(b);
    // Get the absolute path by resolving through the directory handle
    const abs_path = dep.builder.build_root.handle.realpathAlloc(b.allocator, sub_path) catch
        @panic("Failed to resolve headers path");
    return .{ .cwd_relative = abs_path };
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
    @setEvalBranchQuota(10000);

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
    @setEvalBranchQuota(10000);
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

// ============================================================================
// Prerelease Tests
// ============================================================================

test "Prerelease.parse" {
    try std.testing.expectEqual(Prerelease{ .stable = {} }, Prerelease.parse("stable").?);
    try std.testing.expectEqual(Prerelease{ .dev = 1 }, Prerelease.parse("dev1").?);
    try std.testing.expectEqual(Prerelease{ .beta = 2 }, Prerelease.parse("beta2").?);
    try std.testing.expectEqual(Prerelease{ .rc = 3 }, Prerelease.parse("rc3").?);
    try std.testing.expect(Prerelease.parse("invalid") == null);
    try std.testing.expect(Prerelease.parse("") == null);
}

test "Prerelease.order" {
    // dev < beta < rc < stable
    try std.testing.expectEqual(std.math.Order.lt, (Prerelease{ .dev = 1 }).order(.{ .beta = 1 }));
    try std.testing.expectEqual(std.math.Order.lt, (Prerelease{ .beta = 1 }).order(.{ .rc = 1 }));
    try std.testing.expectEqual(std.math.Order.lt, (Prerelease{ .rc = 1 }).order(.stable));

    // Same type, compare numbers
    try std.testing.expectEqual(std.math.Order.lt, (Prerelease{ .beta = 1 }).order(.{ .beta = 2 }));
    try std.testing.expectEqual(std.math.Order.gt, (Prerelease{ .rc = 3 }).order(.{ .rc = 1 }));
    try std.testing.expectEqual(std.math.Order.eq, (Prerelease{ .dev = 5 }).order(.{ .dev = 5 }));
}

// ============================================================================
// Version Tests
// ============================================================================

test "Version.parse stable" {
    const v = Version.parse("4_5_1_stable").?;
    try std.testing.expectEqual(@as(u8, 4), v.major);
    try std.testing.expectEqual(@as(u8, 5), v.minor);
    try std.testing.expectEqual(@as(u8, 1), v.patch);
    try std.testing.expectEqual(Prerelease{ .stable = {} }, v.prerelease);
}

test "Version.parse beta" {
    const v = Version.parse("4_6_0_beta2").?;
    try std.testing.expectEqual(@as(u8, 4), v.major);
    try std.testing.expectEqual(@as(u8, 6), v.minor);
    try std.testing.expectEqual(@as(u8, 0), v.patch);
    try std.testing.expectEqual(Prerelease{ .beta = 2 }, v.prerelease);
}

test "Version.parse rc" {
    const v = Version.parse("4_5_1_rc1").?;
    try std.testing.expectEqual(@as(u8, 4), v.major);
    try std.testing.expectEqual(@as(u8, 5), v.minor);
    try std.testing.expectEqual(@as(u8, 1), v.patch);
    try std.testing.expectEqual(Prerelease{ .rc = 1 }, v.prerelease);
}

test "Version.parse dev" {
    const v = Version.parse("4_6_0_dev6").?;
    try std.testing.expectEqual(@as(u8, 4), v.major);
    try std.testing.expectEqual(@as(u8, 6), v.minor);
    try std.testing.expectEqual(@as(u8, 0), v.patch);
    try std.testing.expectEqual(Prerelease{ .dev = 6 }, v.prerelease);
}

test "Version.parse invalid" {
    try std.testing.expect(Version.parse("4_5_1") == null); // Missing prerelease
    try std.testing.expect(Version.parse("4_5_1_invalid") == null);
    try std.testing.expect(Version.parse("") == null);
}

test "Version.order same base different prerelease" {
    const stable = Version{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable };
    const rc1 = Version{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .rc = 1 } };
    const beta2 = Version{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .beta = 2 } };
    const dev1 = Version{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .dev = 1 } };

    // stable > rc > beta > dev
    try std.testing.expectEqual(std.math.Order.gt, stable.order(rc1));
    try std.testing.expectEqual(std.math.Order.gt, rc1.order(beta2));
    try std.testing.expectEqual(std.math.Order.gt, beta2.order(dev1));
}

test "Version.order different base version" {
    const v451_stable = Version{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable };
    const v450_stable = Version{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable };
    const v460_beta1 = Version{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .beta = 1 } };

    try std.testing.expectEqual(std.math.Order.gt, v451_stable.order(v450_stable));
    // 4.6.0-beta1 > 4.5.1-stable (higher base version wins)
    try std.testing.expectEqual(std.math.Order.gt, v460_beta1.order(v451_stable));
}

// ============================================================================
// Constraint Parse Tests
// ============================================================================

test "Constraint.parse exact stable" {
    const c = Constraint.parse("4.5.1").?;
    try std.testing.expectEqual(@as(u8, 4), c.exact.major);
    try std.testing.expectEqual(@as(u8, 5), c.exact.minor);
    try std.testing.expectEqual(@as(u8, 1), c.exact.patch);
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.exact.prerelease_filter);
}

test "Constraint.parse exact with prerelease" {
    const c = Constraint.parse("4.5.1-beta2").?;
    try std.testing.expectEqual(@as(u8, 4), c.exact.major);
    try std.testing.expectEqual(@as(u8, 5), c.exact.minor);
    try std.testing.expectEqual(@as(u8, 1), c.exact.patch);
    try std.testing.expectEqual(Prerelease{ .beta = 2 }, c.exact.prerelease_filter.exact_prerelease);
}

test "Constraint.parse tilde with prerelease type" {
    const c = Constraint.parse("~4.5-beta").?;
    try std.testing.expectEqual(@as(u8, 4), c.tilde.major);
    try std.testing.expectEqual(@as(u8, 5), c.tilde.minor);
    try std.testing.expectEqual(PrereleaseFilter{ .prerelease_type = .beta }, c.tilde.prerelease_filter);
}

test "Constraint.parse implicit tilde" {
    // "4.5" without patch becomes ~4.5 (any 4.5.x), stable only
    const c = Constraint.parse("4.5").?;
    try std.testing.expectEqual(@as(u8, 4), c.tilde.major);
    try std.testing.expectEqual(@as(u8, 5), c.tilde.minor);
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.tilde.prerelease_filter);
}

test "Constraint.parse implicit caret" {
    // "4" without minor becomes ^4 (any 4.x.x), stable only
    const c = Constraint.parse("4").?;
    try std.testing.expectEqual(@as(u8, 4), c.caret.major);
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.caret.prerelease_filter);
}

test "Constraint.parse tilde" {
    const c = Constraint.parse("~4.5").?;
    try std.testing.expectEqual(@as(u8, 4), c.tilde.major);
    try std.testing.expectEqual(@as(u8, 5), c.tilde.minor);
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.tilde.prerelease_filter);
}

test "Constraint.parse caret" {
    const c = Constraint.parse("^4").?;
    try std.testing.expectEqual(@as(u8, 4), c.caret.major);
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.caret.prerelease_filter);
}

test "Constraint.parse gte" {
    const c = Constraint.parse(">=4.0.0").?;
    try std.testing.expectEqual(@as(u8, 4), c.gte.major);
    try std.testing.expectEqual(@as(u8, 0), c.gte.minor);
    try std.testing.expectEqual(@as(u8, 0), c.gte.patch);
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.gte.prerelease_filter);
}

test "Constraint.parse gte with prerelease" {
    const c = Constraint.parse(">=4.0.0-rc").?;
    try std.testing.expectEqual(@as(u8, 4), c.gte.major);
    try std.testing.expectEqual(PrereleaseFilter{ .prerelease_type = .rc }, c.gte.prerelease_filter);
}

test "Constraint.parse latest" {
    const c = Constraint.parse("latest").?;
    try std.testing.expectEqual(PrereleaseFilter.stable_only, c.latest);
}

test "Constraint.parse latest with prerelease" {
    const c = Constraint.parse("latest-beta").?;
    try std.testing.expectEqual(PrereleaseFilter{ .prerelease_type = .beta }, c.latest);
}

// ============================================================================
// Constraint Match Tests
// ============================================================================

test "Constraint.matches exact stable only" {
    const c = Constraint.parse("4.5.1").?;
    // Matches stable
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
    // Does NOT match prereleases
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .rc = 1 } }));
    // Does NOT match different version
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable }));
}

test "Constraint.matches exact prerelease" {
    const c = Constraint.parse("4.5.1-beta2").?;
    // Matches only that exact prerelease
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .beta = 2 } }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
}

test "Constraint.matches tilde stable only" {
    const c = Constraint.parse("~4.5").?;
    // Matches any 4.5.x stable
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 99, .prerelease = .stable }));
    // Does NOT match prereleases
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
    // Does NOT match different minor
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 4, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!c.matches(.{ .major = 3, .minor = 5, .patch = 0, .prerelease = .stable }));
}

test "Constraint.matches tilde with prerelease type" {
    const c = Constraint.parse("~4.5-beta").?;
    // Matches any 4.5.x beta
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .beta = 5 } }));
    // Does NOT match stable or other prerelease types
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .rc = 1 } }));
}

test "Constraint.matches caret stable only" {
    const c = Constraint.parse("^4").?;
    // Matches any 4.x.x stable
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 0, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 99, .patch = 99, .prerelease = .stable }));
    // Does NOT match prereleases
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
    // Does NOT match different major
    try std.testing.expect(!c.matches(.{ .major = 3, .minor = 0, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!c.matches(.{ .major = 5, .minor = 0, .patch = 0, .prerelease = .stable }));
}

test "Constraint.matches gte stable only" {
    const c = Constraint.parse(">=4.0.0").?;
    // Matches 4.0.0 and above stable
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 0, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 5, .minor = 0, .patch = 0, .prerelease = .stable }));
    // Does NOT match prereleases
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
    // Does NOT match below threshold
    try std.testing.expect(!c.matches(.{ .major = 3, .minor = 9, .patch = 9, .prerelease = .stable }));
}

test "Constraint.matches latest stable only" {
    const c = Constraint.parse("latest").?;
    // Matches any stable version
    try std.testing.expect(c.matches(.{ .major = 1, .minor = 0, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 99, .minor = 99, .patch = 99, .prerelease = .stable }));
    // Does NOT match prereleases
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
}

test "Constraint.matches latest with prerelease" {
    const c = Constraint.parse("latest-dev").?;
    // Matches any dev version
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 99 } }));
    // Does NOT match stable or other types
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
}

// ============================================================================
// parseDependencyName Tests
// ============================================================================

test "parseDependencyName stable" {
    const parsed = parseDependencyName("godot_4_5_1_stable_linux_x86_64").?;
    try std.testing.expectEqual(@as(u8, 4), parsed.version.major);
    try std.testing.expectEqual(@as(u8, 5), parsed.version.minor);
    try std.testing.expectEqual(@as(u8, 1), parsed.version.patch);
    try std.testing.expectEqual(Prerelease{ .stable = {} }, parsed.version.prerelease);
    try std.testing.expectEqualStrings("linux", parsed.platform);
    try std.testing.expectEqualStrings("x86_64", parsed.arch);
}

test "parseDependencyName beta" {
    const parsed = parseDependencyName("godot_4_6_0_beta2_linux_x86_64").?;
    try std.testing.expectEqual(@as(u8, 4), parsed.version.major);
    try std.testing.expectEqual(@as(u8, 6), parsed.version.minor);
    try std.testing.expectEqual(@as(u8, 0), parsed.version.patch);
    try std.testing.expectEqual(Prerelease{ .beta = 2 }, parsed.version.prerelease);
    try std.testing.expectEqualStrings("linux", parsed.platform);
    try std.testing.expectEqualStrings("x86_64", parsed.arch);
}

test "parseDependencyName rc" {
    const parsed = parseDependencyName("godot_4_5_1_rc1_windows_x86_64").?;
    try std.testing.expectEqual(@as(u8, 4), parsed.version.major);
    try std.testing.expectEqual(@as(u8, 5), parsed.version.minor);
    try std.testing.expectEqual(@as(u8, 1), parsed.version.patch);
    try std.testing.expectEqual(Prerelease{ .rc = 1 }, parsed.version.prerelease);
    try std.testing.expectEqualStrings("windows", parsed.platform);
    try std.testing.expectEqualStrings("x86_64", parsed.arch);
}

test "parseDependencyName dev" {
    const parsed = parseDependencyName("godot_4_6_0_dev6_macos_universal").?;
    try std.testing.expectEqual(@as(u8, 4), parsed.version.major);
    try std.testing.expectEqual(@as(u8, 6), parsed.version.minor);
    try std.testing.expectEqual(@as(u8, 0), parsed.version.patch);
    try std.testing.expectEqual(Prerelease{ .dev = 6 }, parsed.version.prerelease);
    try std.testing.expectEqualStrings("macos", parsed.platform);
    try std.testing.expectEqualStrings("universal", parsed.arch);
}

test "parseDependencyName invalid" {
    try std.testing.expect(parseDependencyName("not_godot") == null);
    try std.testing.expect(parseDependencyName("godot_invalid") == null);
    try std.testing.expect(parseDependencyName("godot_4_5_1_linux_x86_64") == null); // Missing prerelease
}

// ============================================================================
// findMatchingDependency Tests
// ============================================================================

test "findMatchingDependency stable only" {
    const deps = [_]struct { []const u8, []const u8 }{
        .{ "godot_4_5_1_stable_linux_x86_64", "hash1" },
        .{ "godot_4_5_1_beta2_linux_x86_64", "hash2" },
        .{ "godot_4_5_0_stable_linux_x86_64", "hash3" },
        .{ "godot_4_4_0_stable_linux_x86_64", "hash4" },
        .{ "godot_3_6_0_stable_linux_x86_64", "hash5" },
        .{ "godot_4_5_1_stable_windows_x86_64", "hash6" },
    };

    // Exact match - stable only
    const exact = findMatchingDependency(&deps, Constraint.parse("4.5.1").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_linux_x86_64", exact);

    // Tilde gets highest stable patch
    const tilde = findMatchingDependency(&deps, Constraint.parse("~4.5").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_linux_x86_64", tilde);

    // Caret gets highest stable minor/patch
    const caret = findMatchingDependency(&deps, Constraint.parse("^4").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_linux_x86_64", caret);

    // Latest gets highest stable overall
    const latest = findMatchingDependency(&deps, Constraint.parse("latest").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_linux_x86_64", latest);

    // Different platform
    const win = findMatchingDependency(&deps, Constraint.parse("latest").?, "windows", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_windows_x86_64", win);
}

test "findMatchingDependency with prerelease filter" {
    const deps = [_]struct { []const u8, []const u8 }{
        .{ "godot_4_6_0_stable_linux_x86_64", "hash1" },
        .{ "godot_4_6_0_beta2_linux_x86_64", "hash2" },
        .{ "godot_4_6_0_beta1_linux_x86_64", "hash3" },
        .{ "godot_4_6_0_rc1_linux_x86_64", "hash4" },
        .{ "godot_4_6_0_dev6_linux_x86_64", "hash5" },
    };

    // Get latest beta
    const beta = findMatchingDependency(&deps, Constraint.parse("4.6-beta").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_beta2_linux_x86_64", beta);

    // Get specific beta
    const beta1 = findMatchingDependency(&deps, Constraint.parse("4.6.0-beta1").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_beta1_linux_x86_64", beta1);

    // Get latest rc
    const rc = findMatchingDependency(&deps, Constraint.parse("~4.6-rc").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_rc1_linux_x86_64", rc);

    // Get latest dev
    const dev = findMatchingDependency(&deps, Constraint.parse("latest-dev").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_dev6_linux_x86_64", dev);
}

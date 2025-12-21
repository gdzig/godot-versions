const std = @import("std");
const root = @import("root");

pub fn build(b: *std.Build) void {
    if (@hasDecl(root, "root") and root.root != @This()) return;

    const target = b.standardTargetOptions(.{});
    const version = b.option([]const u8, "version", "Godot version constraint (default: latest)") orelse "latest";

    const resolved = executableWithVersion(b, target, version) orelse return;

    // Install executable to zig-out/bin/godot
    const install_exe = b.addInstallBinFile(resolved.exe, "godot");
    b.getInstallStep().dependOn(&install_exe.step);

    // Install headers to zig-out/include/
    const headers_dir = headersWithVersion(b, resolved.exe, resolved.version);
    b.getInstallStep().dependOn(&b.addInstallDirectory(.{
        .source_dir = headers_dir,
        .install_dir = .header,
        .install_subdir = "",
    }).step);

    // Run step
    const run = std.Build.Step.Run.create(b, "run godot");
    run.addFileArg(resolved.exe);
    if (b.args) |args| run.addArgs(args);
    run.stdio = .inherit;

    const run_step = b.step("run", "Run Godot");
    run_step.dependOn(&run.step);
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
/// Filter for which prerelease levels to include.
pub const PrereleaseFilter = union(enum) {
    /// Include dev, beta, rc, and stable (everything)
    dev,
    /// Include beta, rc, and stable
    beta,
    /// Include rc and stable
    rc,
    /// Only stable releases (default)
    stable,
    /// Match an exact prerelease (e.g., -beta2, -rc1)
    exact: Prerelease,
};

pub const Constraint = union(enum) {
    /// Version match: "4" (any 4.x.x), "4.5" (any 4.5.x), "4.5.1" (exact)
    version: struct { major: u8, minor: ?u8, patch: ?u8, prerelease_filter: PrereleaseFilter },
    /// Latest available (stable only by default)
    latest: PrereleaseFilter,

    /// Parse a prerelease filter from a string like "stable", "beta", "rc", "dev", "beta2", "rc1"
    fn parsePrereleaseFilter(str: []const u8) ?PrereleaseFilter {
        if (std.mem.eql(u8, str, "stable")) return .stable;
        if (std.mem.eql(u8, str, "rc")) return .rc;
        if (std.mem.eql(u8, str, "beta")) return .beta;
        if (std.mem.eql(u8, str, "dev")) return .dev;
        // Try parsing as exact prerelease (e.g., "beta2", "rc1", "dev3")
        if (Prerelease.parse(str)) |pre| {
            return .{ .exact = pre };
        }
        return null;
    }

    pub fn parse(str: []const u8) ?Constraint {
        if (std.mem.eql(u8, str, "latest")) return .{ .latest = .stable };

        // Bare prerelease names are shortcuts for latest-<name>
        if (std.mem.eql(u8, str, "dev")) return .{ .latest = .dev };
        if (std.mem.eql(u8, str, "beta")) return .{ .latest = .beta };
        if (std.mem.eql(u8, str, "rc")) return .{ .latest = .rc };
        if (std.mem.eql(u8, str, "stable")) return .{ .latest = .stable };

        // Check for prerelease suffix (e.g., "-beta", "-rc", "-stable")
        var prerelease_filter: PrereleaseFilter = .stable;
        var version_part = str;
        if (std.mem.lastIndexOfScalar(u8, str, '-')) |dash_idx| {
            const suffix = str[dash_idx + 1 ..];
            if (parsePrereleaseFilter(suffix)) |filter| {
                prerelease_filter = filter;
                version_part = str[0..dash_idx];
            }
        }

        if (std.mem.eql(u8, version_part, "latest")) return .{ .latest = prerelease_filter };

        // Parse version: "4", "4.5", or "4.5.1"
        var it = std.mem.splitScalar(u8, version_part, '.');
        const major = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
        const minor: ?u8 = if (it.next()) |s| std.fmt.parseInt(u8, s, 10) catch return null else null;
        const patch: ?u8 = if (it.next()) |s| std.fmt.parseInt(u8, s, 10) catch return null else null;
        return .{ .version = .{ .major = major, .minor = minor, .patch = patch, .prerelease_filter = prerelease_filter } };
    }

    fn matchesPrerelease(filter: PrereleaseFilter, prerelease: Prerelease) bool {
        switch (filter) {
            .exact => |exact| return std.meta.eql(prerelease, exact),
            else => {
                // Each filter level includes all more stable levels:
                // dev includes: dev, beta, rc, stable
                // beta includes: beta, rc, stable
                // rc includes: rc, stable
                // stable includes: stable only
                const prerelease_level = prerelease.typeOrder();
                const filter_level: u8 = switch (filter) {
                    .dev => 0,
                    .beta => 1,
                    .rc => 2,
                    .stable => 3,
                    .exact => unreachable,
                };
                return prerelease_level >= filter_level;
            },
        }
    }

    pub fn matches(self: Constraint, version: Version) bool {
        const version_matches = switch (self) {
            .version => |v| blk: {
                if (version.major != v.major) break :blk false;
                if (v.minor) |m| if (version.minor != m) break :blk false;
                if (v.patch) |p| if (version.patch != p) break :blk false;
                break :blk true;
            },
            .latest => true,
        };

        if (!version_matches) return false;

        // Check prerelease filter
        const filter = switch (self) {
            .version => |v| v.prerelease_filter,
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

const MatchedDependency = struct {
    name: []const u8,
    version: Version,
};

fn findMatchingDependency(
    available_deps: []const struct { []const u8, []const u8 },
    constraint: Constraint,
    platform_str: []const u8,
    arch_str: []const u8,
) []const u8 {
    return findMatchingDependencyWithVersion(available_deps, constraint, platform_str, arch_str).name;
}

fn findMatchingDependencyWithVersion(
    available_deps: []const struct { []const u8, []const u8 },
    constraint: Constraint,
    platform_str: []const u8,
    arch_str: []const u8,
) MatchedDependency {
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

    if (best_name == null or best_version == null) {
        @panic("No Godot version found matching constraint for this platform/architecture");
    }

    return .{ .name = best_name.?, .version = best_version.? };
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
///   - "4.5"         - any 4.5.x stable (highest patch)
///   - "4"           - any 4.x.x stable (highest minor/patch)
///   - "latest"      - latest stable version
///
/// Prerelease syntax (append -dev, -beta, -rc, or exact like -beta2):
///   - "4.6-beta"    - any 4.6.x at beta level or above (beta, rc, stable)
///   - "4.6-dev"     - any 4.6.x at dev level or above (everything)
///   - "4.6.0-beta2" - exact beta2 for 4.6.0
///   - "dev"         - latest version including all prereleases
///   - "beta"        - latest version at beta level or above
///
/// Returns null only while waiting for the lazy dependency to be fetched.
/// Panics if no matching version exists or the platform is unsupported.
///
/// Example:
///   const godot = @import("godot");
///   if (godot.executable(b, target, "4.5")) |exe_path| {
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

/// Source for the Godot executable used to generate headers.
pub const HeaderSource = union(enum) {
    /// Use a Godot version from this package's lazy dependencies.
    version: []const u8,
    /// Use a custom Godot executable path.
    exe: std.Build.LazyPath,
};

/// Get the headers directory (containing extension_api.json and gdextension_interface.h).
///
/// This runs the Godot executable to generate the header files on demand.
///
/// Returns null only while waiting for a lazy dependency to be fetched.
pub fn headers(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    source: HeaderSource,
) ?std.Build.LazyPath {
    const resolved = resolveHeaderSource(b, target, source) orelse return null;
    return headersWithVersion(b, resolved.exe, resolved.version);
}

const ResolvedHeaderSource = struct {
    exe: std.Build.LazyPath,
    version: ?Version,
};

fn resolveHeaderSource(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    source: HeaderSource,
) ?ResolvedHeaderSource {
    switch (source) {
        .version => |constraint_str| {
            const resolved = executableWithVersion(b, target, constraint_str) orelse return null;
            return .{ .exe = resolved.exe, .version = resolved.version };
        },
        .exe => |exe| {
            // For custom executables, we don't know the version at build time
            // We'll detect it at runtime
            return .{ .exe = exe, .version = null };
        },
    }
}

const ExecutableWithVersion = struct {
    exe: std.Build.LazyPath,
    version: Version,
};

/// Internal: get executable and resolved version
fn executableWithVersion(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    constraint_str: []const u8,
) ?ExecutableWithVersion {
    @setEvalBranchQuota(10000);

    const constraint = Constraint.parse(constraint_str) orelse
        @panic("Invalid version constraint");

    const plat = targetToPlatformArch(target.result);
    const platform_str = platformToString(plat.platform);
    const arch_str = archToString(plat.arch);

    const godot_builder = getGodotBuilder(b);
    const match = findMatchingDependencyWithVersion(godot_builder.available_deps, constraint, platform_str, arch_str);
    const dep = godot_builder.lazyDependency(match.name, .{}) orelse return null;
    const exe_path = findExecutable(dep) orelse return null;

    return .{ .exe = exe_path, .version = match.version };
}

fn headersWithVersion(
    b: *std.Build,
    godot_exe: std.Build.LazyPath,
    known_version: ?Version,
) std.Build.LazyPath {
    if (known_version) |version| {
        // We know the version at build time, use appropriate flags
        return headersWithFlags(b, godot_exe, version);
    } else {
        // Unknown version (custom exe), use a runtime detection step
        return headersWithRuntimeDetection(b, godot_exe);
    }
}

fn headersWithFlags(
    b: *std.Build,
    godot_exe: std.Build.LazyPath,
    version: Version,
) std.Build.LazyPath {
    // Determine flags based on version:
    // - 4.1.x and 4.2.0-dev[1-5]: --dump-extension-api (no docs)
    // - 4.2.0-dev6+: --dump-extension-api-with-docs
    // - 4.6.0-dev5+: also has --dump-gdextension-interface-json
    const use_docs = shouldUseDocs(version);
    const has_json_interface = hasJsonInterface(version);

    // Use a shell wrapper to cd into output dir and run godot
    const run = b.addSystemCommand(&.{ "sh", "-c" });

    var script: std.ArrayListUnmanaged(u8) = .empty;
    script.appendSlice(b.allocator, "cd \"$1\" && exec \"$2\"") catch @panic("OOM");
    if (use_docs) {
        script.appendSlice(b.allocator, " --dump-extension-api-with-docs") catch @panic("OOM");
    } else {
        script.appendSlice(b.allocator, " --dump-extension-api") catch @panic("OOM");
    }
    script.appendSlice(b.allocator, " --dump-gdextension-interface") catch @panic("OOM");
    if (has_json_interface) {
        script.appendSlice(b.allocator, " --dump-gdextension-interface-json") catch @panic("OOM");
    }
    script.appendSlice(b.allocator, " --headless --quit") catch @panic("OOM");

    run.addArg(script.items);
    run.addArg("--");
    const output_dir = run.addOutputDirectoryArg(".");
    run.addFileArg(godot_exe);

    return output_dir;
}

fn headersWithRuntimeDetection(
    b: *std.Build,
    godot_exe: std.Build.LazyPath,
) std.Build.LazyPath {
    // For unknown versions, run a script that detects and uses appropriate flags
    // This is a fallback for custom executables
    const run = b.addSystemCommand(&.{ "sh", "-c" });

    // Shell script that detects version and runs with appropriate flags
    const script =
        \\set -e
        \\GODOT="$1"
        \\OUTPUT_DIR="$2"
        \\VERSION=$("$GODOT" --version 2>/dev/null | head -1)
        \\
        \\# Parse major.minor from version string (e.g., "4.6.beta2.official" -> "4.6")
        \\MAJOR=$(echo "$VERSION" | cut -d. -f1)
        \\MINOR=$(echo "$VERSION" | cut -d. -f2)
        \\PATCH=$(echo "$VERSION" | cut -d. -f3)
        \\
        \\# Determine flags
        \\API_FLAG="--dump-extension-api-with-docs"
        \\JSON_FLAG=""
        \\
        \\# 4.1.x uses old flag
        \\if [ "$MAJOR" = "4" ] && [ "$MINOR" = "1" ]; then
        \\  API_FLAG="--dump-extension-api"
        \\fi
        \\
        \\# 4.2.0-dev[1-5] uses old flag (patch will be "0" and VERSION contains "dev")
        \\if [ "$MAJOR" = "4" ] && [ "$MINOR" = "2" ] && [ "$PATCH" = "0" ]; then
        \\  case "$VERSION" in
        \\    *dev1*|*dev2*|*dev3*|*dev4*|*dev5*) API_FLAG="--dump-extension-api" ;;
        \\  esac
        \\fi
        \\
        \\# 4.6.0-dev5+ has JSON interface dump
        \\if [ "$MAJOR" -gt "4" ] || ([ "$MAJOR" = "4" ] && [ "$MINOR" -gt "6" ]); then
        \\  JSON_FLAG="--dump-gdextension-interface-json"
        \\elif [ "$MAJOR" = "4" ] && [ "$MINOR" = "6" ]; then
        \\  case "$VERSION" in
        \\    *dev[5-9]*|*beta*|*rc*|*stable*) JSON_FLAG="--dump-gdextension-interface-json" ;;
        \\  esac
        \\fi
        \\
        \\cd "$OUTPUT_DIR"
        \\exec "$GODOT" $API_FLAG --dump-gdextension-interface $JSON_FLAG --headless --quit
    ;

    run.addArg(script);
    run.addArg("--"); // separator
    run.addFileArg(godot_exe);

    const output_dir = run.addOutputDirectoryArg(".");

    return output_dir;
}

/// Check if this version should use --dump-extension-api-with-docs
fn shouldUseDocs(version: Version) bool {
    // 4.1.x: no docs
    if (version.major == 4 and version.minor == 1) return false;

    // 4.2.0-dev[1-5]: no docs
    if (version.major == 4 and version.minor == 2 and version.patch == 0) {
        switch (version.prerelease) {
            .dev => |n| return n >= 6,
            else => return true, // beta, rc, stable all have docs
        }
    }

    // Everything else 4.2+ has docs
    return version.major > 4 or (version.major == 4 and version.minor >= 2);
}

/// Check if this version has --dump-gdextension-interface-json
fn hasJsonInterface(version: Version) bool {
    // Only 4.6.0-dev5 and later
    if (version.major > 4) return true;
    if (version.major < 4) return false;

    // major == 4
    if (version.minor > 6) return true;
    if (version.minor < 6) return false;

    // major == 4, minor == 6
    switch (version.prerelease) {
        .dev => |n| return n >= 5,
        .beta, .rc, .stable => return true,
    }
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

test "Constraint.parse exact version" {
    const c = Constraint.parse("4.5.1").?;
    try std.testing.expectEqual(@as(u8, 4), c.version.major);
    try std.testing.expectEqual(@as(?u8, 5), c.version.minor);
    try std.testing.expectEqual(@as(?u8, 1), c.version.patch);
    try std.testing.expectEqual(PrereleaseFilter.stable, c.version.prerelease_filter);
}

test "Constraint.parse exact with prerelease" {
    const c = Constraint.parse("4.5.1-beta2").?;
    try std.testing.expectEqual(@as(u8, 4), c.version.major);
    try std.testing.expectEqual(@as(?u8, 5), c.version.minor);
    try std.testing.expectEqual(@as(?u8, 1), c.version.patch);
    try std.testing.expectEqual(Prerelease{ .beta = 2 }, c.version.prerelease_filter.exact);
}

test "Constraint.parse exact with prerelease level" {
    const c = Constraint.parse("4.5.1-beta").?;
    try std.testing.expectEqual(@as(u8, 4), c.version.major);
    try std.testing.expectEqual(@as(?u8, 5), c.version.minor);
    try std.testing.expectEqual(@as(?u8, 1), c.version.patch);
    try std.testing.expect(c.version.prerelease_filter == .beta);
}

test "Constraint.parse minor with prerelease" {
    const c = Constraint.parse("4.5-beta").?;
    try std.testing.expectEqual(@as(u8, 4), c.version.major);
    try std.testing.expectEqual(@as(?u8, 5), c.version.minor);
    try std.testing.expectEqual(@as(?u8, null), c.version.patch);
    try std.testing.expectEqual(PrereleaseFilter.beta, c.version.prerelease_filter);
}

test "Constraint.parse minor version" {
    const c = Constraint.parse("4.5").?;
    try std.testing.expectEqual(@as(u8, 4), c.version.major);
    try std.testing.expectEqual(@as(?u8, 5), c.version.minor);
    try std.testing.expectEqual(@as(?u8, null), c.version.patch);
    try std.testing.expectEqual(PrereleaseFilter.stable, c.version.prerelease_filter);
}

test "Constraint.parse major version" {
    const c = Constraint.parse("4").?;
    try std.testing.expectEqual(@as(u8, 4), c.version.major);
    try std.testing.expectEqual(@as(?u8, null), c.version.minor);
    try std.testing.expectEqual(@as(?u8, null), c.version.patch);
    try std.testing.expectEqual(PrereleaseFilter.stable, c.version.prerelease_filter);
}

test "Constraint.parse latest" {
    const c = Constraint.parse("latest").?;
    try std.testing.expectEqual(PrereleaseFilter.stable, c.latest);
}

test "Constraint.parse latest with prerelease" {
    const c = Constraint.parse("latest-beta").?;
    try std.testing.expectEqual(PrereleaseFilter.beta, c.latest);
}

test "Constraint.parse shorthand dev/beta/rc" {
    try std.testing.expectEqual(PrereleaseFilter.dev, Constraint.parse("dev").?.latest);
    try std.testing.expectEqual(PrereleaseFilter.beta, Constraint.parse("beta").?.latest);
    try std.testing.expectEqual(PrereleaseFilter.rc, Constraint.parse("rc").?.latest);
    try std.testing.expectEqual(PrereleaseFilter.stable, Constraint.parse("stable").?.latest);
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

test "Constraint.matches minor stable only" {
    const c = Constraint.parse("4.5").?;
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

test "Constraint.matches minor with prerelease level" {
    const c = Constraint.parse("4.5-beta").?;
    // -beta matches beta, rc, and stable (beta and above)
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .{ .beta = 5 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .rc = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable }));
    // Does NOT match dev (less stable than beta)
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .dev = 1 } }));
}

test "Constraint.matches major stable only" {
    const c = Constraint.parse("4").?;
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

test "Constraint.matches latest stable only" {
    const c = Constraint.parse("latest").?;
    // Matches any stable version
    try std.testing.expect(c.matches(.{ .major = 1, .minor = 0, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(c.matches(.{ .major = 99, .minor = 99, .patch = 99, .prerelease = .stable }));
    // Does NOT match prereleases
    try std.testing.expect(!c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
}

test "Constraint.matches latest with prerelease" {
    const c = Constraint.parse("dev").?;
    // -dev matches everything (dev and above = all)
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 99 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .{ .rc = 1 } }));
    try std.testing.expect(c.matches(.{ .major = 4, .minor = 5, .patch = 0, .prerelease = .stable }));
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

    // Minor version gets highest stable patch
    const minor = findMatchingDependency(&deps, Constraint.parse("4.5").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_linux_x86_64", minor);

    // Major version gets highest stable minor/patch
    const major = findMatchingDependency(&deps, Constraint.parse("4").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_5_1_stable_linux_x86_64", major);

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

    // Get latest at beta level or above (includes beta, rc, stable - returns stable as highest)
    const beta = findMatchingDependency(&deps, Constraint.parse("4.6-beta").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_stable_linux_x86_64", beta);

    // Get specific beta
    const beta1 = findMatchingDependency(&deps, Constraint.parse("4.6.0-beta1").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_beta1_linux_x86_64", beta1);

    // Get latest at rc level or above (includes rc, stable - returns stable as highest)
    const rc = findMatchingDependency(&deps, Constraint.parse("4.6-rc").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_stable_linux_x86_64", rc);

    // Get latest at dev level or above (includes everything - returns stable as highest)
    const dev = findMatchingDependency(&deps, Constraint.parse("dev").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_stable_linux_x86_64", dev);

    // Get exact dev6
    const dev6 = findMatchingDependency(&deps, Constraint.parse("4.6.0-dev6").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_dev6_linux_x86_64", dev6);

    // Get exact rc1
    const rc1 = findMatchingDependency(&deps, Constraint.parse("4.6.0-rc1").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_rc1_linux_x86_64", rc1);

    // Get exact beta2
    const beta2 = findMatchingDependency(&deps, Constraint.parse("4.6.0-beta2").?, "linux", "x86_64");
    try std.testing.expectEqualStrings("godot_4_6_0_beta2_linux_x86_64", beta2);
}

// ============================================================================
// shouldUseDocs Tests
// ============================================================================

test "shouldUseDocs 4.1.x returns false" {
    // 4.1.x never has docs
    try std.testing.expect(!shouldUseDocs(.{ .major = 4, .minor = 1, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!shouldUseDocs(.{ .major = 4, .minor = 1, .patch = 4, .prerelease = .stable }));
    try std.testing.expect(!shouldUseDocs(.{ .major = 4, .minor = 1, .patch = 0, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(!shouldUseDocs(.{ .major = 4, .minor = 1, .patch = 0, .prerelease = .{ .dev = 1 } }));
}

test "shouldUseDocs 4.2.0-dev[1-5] returns false" {
    try std.testing.expect(!shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .{ .dev = 1 } }));
    try std.testing.expect(!shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .{ .dev = 5 } }));
}

test "shouldUseDocs 4.2.0-dev6+ returns true" {
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .{ .dev = 6 } }));
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .{ .dev = 10 } }));
}

test "shouldUseDocs 4.2.0-beta+ returns true" {
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .{ .rc = 1 } }));
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 2, .patch = 0, .prerelease = .stable }));
}

test "shouldUseDocs 4.3+ returns true" {
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 3, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
    try std.testing.expect(shouldUseDocs(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 1 } }));
    try std.testing.expect(shouldUseDocs(.{ .major = 5, .minor = 0, .patch = 0, .prerelease = .stable }));
}

// ============================================================================
// hasJsonInterface Tests
// ============================================================================

test "hasJsonInterface before 4.6 returns false" {
    try std.testing.expect(!hasJsonInterface(.{ .major = 4, .minor = 5, .patch = 1, .prerelease = .stable }));
    try std.testing.expect(!hasJsonInterface(.{ .major = 4, .minor = 4, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!hasJsonInterface(.{ .major = 4, .minor = 1, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(!hasJsonInterface(.{ .major = 3, .minor = 6, .patch = 0, .prerelease = .stable }));
}

test "hasJsonInterface 4.6.0-dev[1-4] returns false" {
    try std.testing.expect(!hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 1 } }));
    try std.testing.expect(!hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 4 } }));
}

test "hasJsonInterface 4.6.0-dev5+ returns true" {
    try std.testing.expect(hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 5 } }));
    try std.testing.expect(hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .dev = 6 } }));
}

test "hasJsonInterface 4.6.0-beta+ returns true" {
    try std.testing.expect(hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .beta = 1 } }));
    try std.testing.expect(hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .{ .rc = 1 } }));
    try std.testing.expect(hasJsonInterface(.{ .major = 4, .minor = 6, .patch = 0, .prerelease = .stable }));
}

test "hasJsonInterface 4.7+ returns true" {
    try std.testing.expect(hasJsonInterface(.{ .major = 4, .minor = 7, .patch = 0, .prerelease = .stable }));
    try std.testing.expect(hasJsonInterface(.{ .major = 5, .minor = 0, .patch = 0, .prerelease = .stable }));
}

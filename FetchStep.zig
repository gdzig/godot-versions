//! A build step that fetches and extracts a zip file from a URL.
//! Uses `zig fetch` subprocess for TLS support, then extracts the archive.

const std = @import("std");
const Step = std.Build.Step;
const Io = std.Io;

const FetchStep = @This();

step: Step,
url: []const u8,
expected_hash: []const u8,
generated_directory: std.Build.GeneratedFile,
generated_executable: std.Build.GeneratedFile,

pub const base_id: Step.Id = .custom;

pub fn create(owner: *std.Build, name: []const u8, url: []const u8, expected_hash: []const u8) *FetchStep {
    const fetch = owner.allocator.create(FetchStep) catch @panic("OOM");
    fetch.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = name,
            .owner = owner,
            .makeFn = make,
        }),
        .url = owner.dupe(url),
        .expected_hash = owner.dupe(expected_hash),
        .generated_directory = .{ .step = &fetch.step },
        .generated_executable = .{ .step = &fetch.step },
    };
    return fetch;
}

pub fn getDirectory(fetch: *FetchStep) std.Build.LazyPath {
    return .{ .generated = .{ .file = &fetch.generated_directory } };
}

pub fn getExecutable(fetch: *FetchStep) std.Build.LazyPath {
    return .{ .generated = .{ .file = &fetch.generated_executable } };
}

fn make(step: *Step, _: Step.MakeOptions) !void {
    const b = step.owner;
    const arena = b.allocator;
    const io = b.graph.io;
    const fetch: *FetchStep = @fieldParentPtr("step", step);

    // Use the expected hash as the cache key
    var man = b.graph.cache.obtain();
    defer man.deinit();

    man.hash.addBytes(fetch.url);
    man.hash.addBytes(fetch.expected_hash);

    // Check cache
    if (try step.cacheHitAndWatch(&man)) {
        const digest = man.final();
        fetch.generated_directory.path = try b.cache_root.join(arena, &.{ "o", &digest });
        // Read the executable name from the marker file
        const exe_name = readExeName(arena, io, b.cache_root.handle, "o" ++ std.fs.path.sep_str ++ digest) catch |err| {
            return step.fail("failed to read cached executable name: {s}", .{@errorName(err)});
        };
        fetch.generated_executable.path = try b.cache_root.join(arena, &.{ "o", &digest, exe_name });
        step.result_cached = true;
        return;
    }

    const digest = man.final();
    const cache_path = "o" ++ std.fs.path.sep_str ++ digest;

    // Create output directory
    var cache_dir = b.cache_root.handle.createDirPathOpen(io, cache_path, .{ .open_options = .{ .iterate = true } }) catch |err| {
        return step.fail("unable to make cache path '{s}': {s}", .{
            cache_path, @errorName(err),
        });
    };
    defer cache_dir.close(io);

    fetch.generated_directory.path = try b.cache_root.join(arena, &.{ "o", &digest });

    // Use `zig fetch` to download the archive - it has TLS support
    // zig fetch outputs the hash of the fetched package
    const global_cache_path = b.graph.global_cache_root.path orelse {
        return step.fail("global cache root path is not available", .{});
    };

    var zig_fetch = try std.process.spawn(io, .{
        .argv = &.{ "zig", "fetch", "--global-cache-dir", global_cache_path, fetch.url },
        .stderr = .ignore,
        .stdout = .pipe,
    });

    var read_buf: [4096]u8 = undefined;
    var stdout_reader = zig_fetch.stdout.?.readerStreaming(io, &read_buf);
    const stdout = try stdout_reader.interface.allocRemaining(arena, .limited(1024 * 1024));

    const result = try zig_fetch.wait(io);

    if (result != .exited or result.exited != 0) {
        return step.fail("'zig fetch' failed", .{});
    }

    // zig fetch outputs the hash (with trailing newline)
    const pkg_hash = std.mem.trim(u8, stdout, "\n\r ");

    // Verify the hash matches what we expected
    if (!std.mem.eql(u8, pkg_hash, fetch.expected_hash)) {
        return step.fail("hash mismatch: expected '{s}', got '{s}'", .{ fetch.expected_hash, pkg_hash });
    }

    // Package is stored in <global_cache>/p/<hash>
    const pkg_subpath = try std.fs.path.join(arena, &.{ "p", pkg_hash });

    // The fetched path is a directory containing the extracted archive
    // Copy contents to our cache directory
    var src_dir = b.graph.global_cache_root.handle.openDir(io, pkg_subpath, .{ .iterate = true }) catch |err| {
        return step.fail("failed to open fetched directory 'p/{s}': {s}", .{ pkg_hash, @errorName(err) });
    };
    defer src_dir.close(io);

    // Copy all files from the fetched directory to our cache
    var iter = src_dir.iterate();
    while (iter.next(io) catch |err| {
        return step.fail("failed to iterate source directory: {s}", .{@errorName(err)});
    }) |entry| {
        copyEntry(io, src_dir, cache_dir, entry.name, entry.kind) catch |err| {
            return step.fail("failed to copy '{s}': {s}", .{ entry.name, @errorName(err) });
        };
    }

    // Find the Godot executable and store its path
    const exe_name = try findGodotExecutable(step, io, cache_dir);
    fetch.generated_executable.path = try b.cache_root.join(arena, &.{ "o", &digest, exe_name });

    // Write the executable name to a marker file for cache hits
    cache_dir.writeFile(io, .{ .sub_path = ".godot_exe", .data = exe_name }) catch |err| {
        return step.fail("failed to write executable marker: {s}", .{@errorName(err)});
    };

    // Write the manifest to finalize the cache entry
    try man.writeManifest();
}

fn readExeName(arena: std.mem.Allocator, io: Io, cache_root: Io.Dir, cache_path: []const u8) ![]const u8 {
    var dir = try cache_root.openDir(io, cache_path, .{});
    defer dir.close(io);
    const file = try dir.openFile(io, ".godot_exe", .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    return reader.interface.allocRemaining(arena, .limited(std.fs.max_path_bytes));
}

fn copyEntry(io: Io, src_dir: Io.Dir, dst_dir: Io.Dir, name: []const u8, kind: Io.File.Kind) !void {
    switch (kind) {
        .file => {
            try src_dir.copyFile(name, dst_dir, name, io, .{});
        },
        .directory => {
            var src_sub = try src_dir.openDir(io, name, .{ .iterate = true });
            defer src_sub.close(io);
            var dst_sub = try dst_dir.createDirPathOpen(io, name, .{});
            defer dst_sub.close(io);

            var iter = src_sub.iterate();
            while (try iter.next(io)) |entry| {
                try copyEntry(io, src_sub, dst_sub, entry.name, entry.kind);
            }
        },
        .sym_link => {
            var link_buf: [std.fs.max_path_bytes]u8 = undefined;
            const len = try src_dir.readLink(io, name, &link_buf);
            const target = link_buf[0..len];
            try dst_dir.symLink(io, target, name, .{});
        },
        else => {},
    }
}

/// Find the Godot executable in the directory
fn findGodotExecutable(step: *Step, io: Io, dir: Io.Dir) ![]const u8 {
    var iter = dir.iterate();
    while (iter.next(io) catch |err| {
        return step.fail("failed to iterate directory: {s}", .{@errorName(err)});
    }) |entry| {
        const name = entry.name;

        // macOS app bundle - return path to executable inside
        if (entry.kind == .directory and std.mem.eql(u8, name, "Godot.app")) {
            return "Godot.app/Contents/MacOS/Godot";
        }

        // macOS app bundle extracted by zig fetch (strips .app wrapper, leaving just Contents/)
        if (entry.kind == .directory and std.mem.eql(u8, name, "Contents")) {
            return "Contents/MacOS/Godot";
        }

        if (entry.kind != .file) continue;

        // Match Godot executable: Godot_v* or Godot.* (but skip console versions)
        if (std.mem.startsWith(u8, name, "Godot_v") or std.mem.startsWith(u8, name, "Godot.")) {
            if (std.mem.indexOf(u8, name, "_console") != null) continue;
            return step.owner.dupe(name);
        }
    }

    return step.fail("could not find Godot executable in extracted archive", .{});
}

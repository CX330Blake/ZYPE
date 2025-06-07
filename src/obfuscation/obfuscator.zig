const std = @import("std");
const output = @import("../io/output.zig");
const stdout = std.io.getStdOut().writer();
const Allocator = std.mem.Allocator;

// IPv4 Obfuscation Functions

/// Function takes in 4 raw bytes and returns them in an IPv4 string format
pub fn generateIpv4(allocator: Allocator, a: u8, b: u8, c: u8, d: u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ a, b, c, d });
}

/// Generate the IPv4 output representation of the shellcode
pub fn generateIpv4Output(allocator: Allocator, shellcode: []const u8) !bool {
    if (shellcode.len == 0) {
        return false;
    }

    try output.printInfo("const IPV4_ARRAY: [{}][]const u8 = [_][]const u8{{\n", .{(shellcode.len + 3) / 4});

    var i: usize = 0;
    while (i < shellcode.len) : (i += 4) {
        const b1 = shellcode[i];
        const b2 = if (i + 1 < shellcode.len) shellcode[i + 1] else 0;
        const b3 = if (i + 2 < shellcode.len) shellcode[i + 2] else 0;
        const b4 = if (i + 3 < shellcode.len) shellcode[i + 3] else 0;

        const ip = try generateIpv4(allocator, b1, b2, b3, b4);
        defer allocator.free(ip);

        try output.printInfo("    \"{s}\"", .{ip});
        if (i + 4 < shellcode.len) try output.printInfo(",", .{});
        try output.printInfo("\n", .{});
    }

    try output.printInfo("}};\n\n", .{});
    return true;
}

// IPv6 Obfuscation Functions

/// Generate IPv6 address from 16 bytes
pub fn generateIpv6(allocator: Allocator, bytes: [16]u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
        (@as(u16, bytes[0]) << 8) | bytes[1],
        (@as(u16, bytes[2]) << 8) | bytes[3],
        (@as(u16, bytes[4]) << 8) | bytes[5],
        (@as(u16, bytes[6]) << 8) | bytes[7],
        (@as(u16, bytes[8]) << 8) | bytes[9],
        (@as(u16, bytes[10]) << 8) | bytes[11],
        (@as(u16, bytes[12]) << 8) | bytes[13],
        (@as(u16, bytes[14]) << 8) | bytes[15],
    });
}

/// Generate the IPv6 output representation of the shellcode
pub fn generateIpv6Output(allocator: Allocator, shellcode: []const u8) !bool {
    if (shellcode.len == 0) {
        return false;
    }

    const num_addresses = (shellcode.len + 15) / 16;
    try output.printInfo("const IPV6_ARRAY: [{}][]const u8 = [_][]const u8{{\n", .{num_addresses});

    var i: usize = 0;
    while (i < shellcode.len) : (i += 16) {
        var bytes: [16]u8 = std.mem.zeroes([16]u8);

        // Copy available bytes, rest remain zero
        const end = @min(i + 16, shellcode.len);
        @memcpy(bytes[0 .. end - i], shellcode[i..end]);

        const ipv6 = try generateIpv6(allocator, bytes);
        defer allocator.free(ipv6);

        try output.printInfo("    \"{s}\"", .{ipv6});
        if (i + 16 < shellcode.len) try output.printInfo(",", .{});
        try output.printInfo("\n", .{});
    }

    try output.printInfo("}};\n\n", .{});
    return true;
}

// MAC Address Obfuscation Functions

/// Generate MAC address from 6 bytes
pub fn generateMac(allocator: Allocator, bytes: [6]u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5] });
}

/// Generate the MAC address output representation of the shellcode
pub fn generateMacOutput(allocator: Allocator, shellcode: []const u8) !bool {
    if (shellcode.len == 0) {
        return false;
    }

    const num_addresses = (shellcode.len + 5) / 6;
    try output.printInfo("const MAC_ARRAY: [{}][]const u8 = [_][]const u8{{\n", .{num_addresses});

    var i: usize = 0;
    while (i < shellcode.len) : (i += 6) {
        var bytes: [6]u8 = std.mem.zeroes([6]u8);

        // Copy available bytes, rest remain zero
        const end = @min(i + 6, shellcode.len);
        @memcpy(bytes[0 .. end - i], shellcode[i..end]);

        const mac = try generateMac(allocator, bytes);
        defer allocator.free(mac);

        try output.printInfo("    \"{s}\"", .{mac});
        if (i + 6 < shellcode.len) try output.printInfo(",", .{});
        try output.printInfo("\n", .{});
    }

    try output.printInfo("}};\n\n", .{});
    return true;
}

// UUID Obfuscation Functions

/// Generate UUID from 16 bytes using Windows GUID byte ordering
/// This matches the Rust implementation and Windows UuidFromStringA behavior
pub fn generateUuid(allocator: Allocator, bytes: [16]u8) ![]u8 {
    // Windows GUID byte ordering (matching Rust code):
    // bytes[3], bytes[2], bytes[1], bytes[0] - first 4 bytes (little-endian)
    // bytes[5], bytes[4] - next 2 bytes (little-endian)
    // bytes[7], bytes[6] - next 2 bytes (little-endian)
    // bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15] - last 8 bytes (big-endian)
    return try std.fmt.allocPrint(allocator, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        bytes[3], bytes[2], bytes[1], bytes[0], // Data1: little-endian 32-bit
        bytes[5], bytes[4], // Data2: little-endian 16-bit
        bytes[7], bytes[6], // Data3: little-endian 16-bit
        bytes[8],  bytes[9], // Data4[0-1]: big-endian
        bytes[10], bytes[11],
        bytes[12], bytes[13],
        bytes[14], bytes[15], // Data4[2-7]: big-endian
    });
}

/// Generate the UUID output representation of the shellcode
/// Uses Windows GUID byte ordering to match the decryption function
pub fn generateUuidOutput(allocator: Allocator, shellcode: []const u8) !bool {
    if (shellcode.len == 0) {
        return false;
    }

    const num_uuids = (shellcode.len + 15) / 16;
    try output.printInfo("const UUID_ARRAY: [{}][]const u8 = [_][]const u8{{\n", .{num_uuids});

    var i: usize = 0;
    var chunk_index: usize = 0;
    while (i < shellcode.len) : (i += 16) {
        var bytes: [16]u8 = std.mem.zeroes([16]u8);

        // Copy available bytes, rest remain zero
        const end = @min(i + 16, shellcode.len);
        @memcpy(bytes[0 .. end - i], shellcode[i..end]);

        const uuid = try generateUuid(allocator, bytes);
        defer allocator.free(uuid);

        try output.printInfo("    \"{s}\"", .{uuid});

        // Add comma if not the last element
        if (chunk_index < num_uuids - 1) {
            try output.printInfo(",", .{});
        }
        try output.printInfo("\n", .{});

        chunk_index += 1;
    }

    try output.printInfo("}};\n\n", .{});
    return true;
}

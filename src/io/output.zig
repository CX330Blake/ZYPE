const std = @import("std");
const stdout = std.io.getStdOut().writer();
const build_options = @import("build_options");
const version = build_options.version_string;
const output = @import("../io/output.zig");

const Methods = @import("../encryption/encryptor.zig").Methods;

pub const banner =
    \\ ___  _   _ ___  ____ 
    \\   /   \_/  |__] |___ 
    \\  /__   |   |    |___ 
;

pub fn printInfo(comptime format: []const u8, args: anytype) !void {
    try stdout.print(format, args);
}

pub fn printError(comptime format: []const u8, args: anytype) !void {
    try stdout.print("\x1b[31m", .{});
    try stdout.print(format, args);
    try stdout.print("\x1b[0m", .{});
}

pub fn printSuccess(comptime format: []const u8, args: anytype) !void {
    try stdout.print("\x1b[32m", .{});
    try stdout.print(format, args);
    try stdout.print("\x1b[0m", .{});
}

pub fn printVersion() !void {
    try printInfo("{s}\n\n", .{banner});
    try printInfo("ZYPE shellcode encryptor v{s}\n", .{version});
    try printInfo("Copyright (C) 2025 @CX330Blake.\n", .{});
    try printInfo("All rights reserved.\n\n", .{});
}

pub fn printUsage() !void {
    try printVersion();
    try stdout.print(
        \\ZYPE v{s} - Shellcode encryptor and obfuscator
        \\
        \\Usage: zype [options]
        \\
        \\Options:
        \\  -h, --help              Show this help message
        \\  -v, --version           Show version information
        \\  -i, --interactive       Interactive mode (guided setup)
        \\  -m, --method <type>     Encryption/obfuscation method
        \\  -f, --file <path>       Input shellcode file path
        \\
        \\Supported Methods:
        \\  mac                     MAC address obfuscation
        \\  ipv4                    IPv4 address obfuscation
        \\  ipv6                    IPv6 address obfuscation
        \\  uuid                    UUID obfuscation
        \\  aes                     AES encryption (CTR mode)
        \\  rc4                     RC4 encryption
        \\  xor                     XOR encryption
        \\
        \\Examples:
        \\  zype -i                                         # Interactive mode
        \\  zype -m aes -f shellcode.bin > shellcode.zig    # AES encrypt shellcode.bin
        \\  zype -m mac -f shellcode.bin                    # MAC address obfuscation
        \\  zype --method rc4 --file sc.bin                 # RC4 encryption
        \\
        \\Notes:
        \\  - Interactive mode provides guided setup for all options
        \\  - Output includes both obfuscated data and decoder template
        \\  - Generated code is cross-platform compatible (no Windows APIs)
        \\
    , .{version});
}

pub fn printMenu() !void {
    const MethodsTag = @typeInfo(Methods).@"union".tag_type.?;
    const method_tag_names = @typeInfo(MethodsTag).@"enum".fields;

    try printVersion();

    comptime var i = 0;
    inline while (i < method_tag_names.len) : (i += 1) {
        if (i % 2 == 0) {
            try printInfo("({}) {s} \t", .{ i, method_tag_names[i].name });
        } else {
            try printInfo("({}) {s}\n", .{ i, method_tag_names[i].name });
        }
    }
    try printInfo("\n\nChoose the encryption/obfuscation method: (input the number): ", .{});
}

pub fn printDecodeFunctionality(transform_type: []const u8, array_str: []const u8, size: usize) !void {
    if (std.mem.eql(u8, transform_type, "mac")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("const net = std.net;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("const NUMBER_OF_ELEMENTS: usize = {};\n", .{size});
        try output.printInfo("\n", .{});
        try output.printInfo("fn macDeobfuscation(mac_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {{\n", .{});
        try output.printInfo("    var buffer = try allocator.alloc(u8, mac_array.len * 6);\n", .{});
        try output.printInfo("    var offset: usize = 0;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    for (mac_array) |mac| {{\n", .{});
        try output.printInfo("        var parts = std.mem.splitScalar(u8, mac, ':');\n", .{});
        try output.printInfo("        var i: usize = 0;\n", .{});
        try output.printInfo("        while (parts.next()) |part| : (i += 1) {{\n", .{});
        try output.printInfo("            if (i >= 6) return error.InvalidMacFormat;\n", .{});
        try output.printInfo("            buffer[offset + i] = std.fmt.parseInt(u8, part, 16) catch return error.InvalidHexDigit;\n", .{});
        try output.printInfo("        }}\n", .{});
        try output.printInfo("        if (i != 6) return error.InvalidMacFormat;\n", .{});
        try output.printInfo("        offset += 6;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    return buffer;\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};\n", .{});
        try output.printInfo("    defer _ = gpa.deinit();\n", .{});
        try output.printInfo("    const allocator = gpa.allocator();\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    const shellcode = try macDeobfuscation(&MAC_ARRAY, allocator);\n", .{});
        try output.printInfo("    defer allocator.free(shellcode);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{shellcode.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{shellcode}});\n", .{});
        try output.printInfo("}}\n", .{});
    } else if (std.mem.eql(u8, transform_type, "ipv4")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("const net = std.net;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("const NUMBER_OF_ELEMENTS: usize = {};\n", .{size});
        try output.printInfo("\n", .{});
        try output.printInfo("fn ipv4Deobfuscation(ipv4_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {{\n", .{});
        try output.printInfo("    var buffer = try allocator.alloc(u8, ipv4_array.len * 4);\n", .{});
        try output.printInfo("    var offset: usize = 0;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    for (ipv4_array) |ip| {{\n", .{});
        try output.printInfo("        const addr = net.Address.parseIp4(ip, 0) catch return error.InvalidIpFormat;\n", .{});
        try output.printInfo("        const ip_bytes = @as([4]u8, @bitCast(addr.in.sa.addr));\n", .{});
        try output.printInfo("        @memcpy(buffer[offset..offset + 4], &ip_bytes);\n", .{});
        try output.printInfo("        offset += 4;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    return buffer;\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};\n", .{});
        try output.printInfo("    defer _ = gpa.deinit();\n", .{});
        try output.printInfo("    const allocator = gpa.allocator();\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    const shellcode = try ipv4Deobfuscation(&IPV4_ARRAY, allocator);\n", .{});
        try output.printInfo("    defer allocator.free(shellcode);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{shellcode.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{shellcode}});\n", .{});
        try output.printInfo("}}\n", .{});
    } else if (std.mem.eql(u8, transform_type, "ipv6")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("const net = std.net;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("const NUMBER_OF_ELEMENTS: usize = {};\n", .{size});
        try output.printInfo("\n", .{});
        try output.printInfo("fn ipv6Deobfuscation(ipv6_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {{\n", .{});
        try output.printInfo("    var buffer = try allocator.alloc(u8, ipv6_array.len * 16);\n", .{});
        try output.printInfo("    var offset: usize = 0;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    for (ipv6_array) |ip| {{\n", .{});
        try output.printInfo("        const addr = net.Address.parseIp6(ip, 0) catch return error.InvalidIpFormat;\n", .{});
        try output.printInfo("        const ip_bytes = @as([16]u8, @bitCast(addr.in6.sa.addr));\n", .{});
        try output.printInfo("        @memcpy(buffer[offset..offset + 16], &ip_bytes);\n", .{});
        try output.printInfo("        offset += 16;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    return buffer;\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};\n", .{});
        try output.printInfo("    defer _ = gpa.deinit();\n", .{});
        try output.printInfo("    const allocator = gpa.allocator();\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    const shellcode = try ipv6Deobfuscation(&IPV6_ARRAY, allocator);\n", .{});
        try output.printInfo("    defer allocator.free(shellcode);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{shellcode.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{shellcode}});\n", .{});
        try output.printInfo("}}\n", .{});
    } else if (std.mem.eql(u8, transform_type, "uuid")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("const NUMBER_OF_ELEMENTS: usize = {};\n", .{size});
        try output.printInfo("\n", .{});
        try output.printInfo("fn uuidDeobfuscation(uuid_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {{\n", .{});
        try output.printInfo("    var buffer = try allocator.alloc(u8, uuid_array.len * 16);\n", .{});
        try output.printInfo("    var offset: usize = 0;\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    for (uuid_array) |uuid| {{\n", .{});
        try output.printInfo("        var clean_uuid = std.ArrayList(u8).init(allocator);\n", .{});
        try output.printInfo("        defer clean_uuid.deinit();\n", .{});
        try output.printInfo("        \n", .{});
        try output.printInfo("        // Remove hyphens from UUID\n", .{});
        try output.printInfo("        for (uuid) |c| {{\n", .{});
        try output.printInfo("            if (c != '-') {{\n", .{});
        try output.printInfo("                try clean_uuid.append(c);\n", .{});
        try output.printInfo("            }}\n", .{});
        try output.printInfo("        }}\n", .{});
        try output.printInfo("        \n", .{});
        try output.printInfo("        if (clean_uuid.items.len != 32) return error.InvalidUuidFormat;\n", .{});
        try output.printInfo("        \n", .{});
        try output.printInfo("        // Parse hex string to bytes\n", .{});
        try output.printInfo("        for (0..16) |i| {{\n", .{});
        try output.printInfo("            const hex_pair = clean_uuid.items[i * 2..i * 2 + 2];\n", .{});
        try output.printInfo("            buffer[offset + i] = std.fmt.parseInt(u8, hex_pair, 16) catch return error.InvalidHexDigit;\n", .{});
        try output.printInfo("        }}\n", .{});
        try output.printInfo("        offset += 16;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    return buffer;\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};\n", .{});
        try output.printInfo("    defer _ = gpa.deinit();\n", .{});
        try output.printInfo("    const allocator = gpa.allocator();\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    const shellcode = try uuidDeobfuscation(&UUID_ARRAY, allocator);\n", .{});
        try output.printInfo("    defer allocator.free(shellcode);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{shellcode.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{shellcode}});\n", .{});
        try output.printInfo("}}\n", .{});
    } else if (std.mem.eql(u8, transform_type, "aes")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("fn aesDecryption(ciphertext: []u8, key: []const u8, iv: []const u8) !void {{\n", .{});
        try output.printInfo("    switch (key.len) {{\n", .{});
        try output.printInfo("        16 => {{\n", .{});
        try output.printInfo("            const key_array: [16]u8 = key[0..16].*;\n", .{});
        try output.printInfo("            const ctx = std.crypto.core.aes.Aes128.initEnc(key_array);\n", .{});
        try output.printInfo("            try aesDecryptWithContext(ciphertext, ctx, iv);\n", .{});
        try output.printInfo("        }},\n", .{});
        try output.printInfo("        32 => {{\n", .{});
        try output.printInfo("            const key_array: [32]u8 = key[0..32].*;\n", .{});
        try output.printInfo("            const ctx = std.crypto.core.aes.Aes256.initEnc(key_array);\n", .{});
        try output.printInfo("            try aesDecryptWithContext(ciphertext, ctx, iv);\n", .{});
        try output.printInfo("        }},\n", .{});
        try output.printInfo("        else => return error.InvalidKeyLength,\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("fn aesDecryptWithContext(data: []u8, ctx: anytype, iv: []const u8) !void {{\n", .{});
        try output.printInfo("    // CTR mode decryption is same as encryption\n", .{});
        try output.printInfo("    var counter: [16]u8 = undefined;\n", .{});
        try output.printInfo("    @memcpy(&counter, iv);\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    var offset: usize = 0;\n", .{});
        try output.printInfo("    while (offset < data.len) {{\n", .{});
        try output.printInfo("        var keystream: [16]u8 = undefined;\n", .{});
        try output.printInfo("        ctx.encrypt(&keystream, &counter);\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("        const block_size = @min(16, data.len - offset);\n", .{});
        try output.printInfo("        for (0..block_size) |i| {{\n", .{});
        try output.printInfo("            data[offset + i] ^= keystream[i];\n", .{});
        try output.printInfo("        }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("        // Increment counter\n", .{});
        try output.printInfo("        var carry: u16 = 1;\n", .{});
        try output.printInfo("        var i: usize = 15;\n", .{});
        try output.printInfo("        while (carry > 0 and i < 16) {{\n", .{});
        try output.printInfo("            carry += counter[i];\n", .{});
        try output.printInfo("            counter[i] = @intCast(carry & 0xFF);\n", .{});
        try output.printInfo("            carry >>= 8;\n", .{});
        try output.printInfo("            if (i == 0) break;\n", .{});
        try output.printInfo("            i -= 1;\n", .{});
        try output.printInfo("        }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("        offset += block_size;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var ciphertext = AES_CIPHERTEXT;\n", .{});
        try output.printInfo("    try aesDecryption(&ciphertext, &AES_KEY, &AES_IV);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{ciphertext.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{ciphertext}});\n", .{});
        try output.printInfo("}}\n", .{});
    } else if (std.mem.eql(u8, transform_type, "rc4")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("fn rc4Decryption(key: []const u8, data: []u8) void {{\n", .{});
        try output.printInfo("    // RC4 Key Scheduling Algorithm (KSA)\n", .{});
        try output.printInfo("    var s: [256]u8 = undefined;\n", .{});
        try output.printInfo("    for (0..256) |i| {{\n", .{});
        try output.printInfo("        s[i] = @as(u8, @intCast(i));\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    var j: u32 = 0;\n", .{});
        try output.printInfo("    for (0..256) |i| {{\n", .{});
        try output.printInfo("        j = (j + s[i] + key[i % key.len]) % @as(u32, 256);\n", .{});
        try output.printInfo("        const temp = s[i];\n", .{});
        try output.printInfo("        s[i] = s[j];\n", .{});
        try output.printInfo("        s[j] = temp;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    // RC4 Pseudo-Random Generation Algorithm (PRGA)\n", .{});
        try output.printInfo("    var i: u32 = 0;\n", .{});
        try output.printInfo("    j = 0;\n", .{});
        try output.printInfo("    for (data) |*byte| {{\n", .{});
        try output.printInfo("        i = (i + 1) % @as(u32, 256);\n", .{});
        try output.printInfo("        j = (j + s[i]) % @as(u32, 256);\n", .{});
        try output.printInfo("        const temp = s[i];\n", .{});
        try output.printInfo("        s[i] = s[j];\n", .{});
        try output.printInfo("        s[j] = temp;\n", .{});
        try output.printInfo("        const k = (@as(u32, s[i]) + @as(u32, s[j])) % @as(u32, 256);\n", .{});
        try output.printInfo("        const keystream_byte = s[k];\n", .{});
        try output.printInfo("        byte.* ^= keystream_byte;\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var ciphertext = RC4_CIPHERTEXT;\n", .{});
        try output.printInfo("    rc4Decryption(&RC4_KEY, &ciphertext);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{ciphertext.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{ciphertext}});\n", .{});
        try output.printInfo("}}\n", .{});
    } else if (std.mem.eql(u8, transform_type, "xor")) {
        try output.printInfo("const std = @import(\"std\");\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("{s}", .{std.mem.trimRight(u8, array_str, " \n\t")});
        try output.printInfo("\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("/// XOR decryption function - same as encryption since XOR is symmetric\n", .{});
        try output.printInfo("/// Uses multi-byte key and iterates each byte as different key in each iteration\n", .{});
        try output.printInfo("fn xorDecryption(shellcode: []u8, key: []const u8) void {{\n", .{});
        try output.printInfo("    const key_len = key.len;\n", .{});
        try output.printInfo("    if (key_len == 0) return; // Avoid division by zero\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    var j: usize = 0;\n", .{});
        try output.printInfo("    for (shellcode) |*byte| {{\n", .{});
        try output.printInfo("        byte.* = byte.* ^ key[j];\n", .{});
        try output.printInfo("        j += 1;\n", .{});
        try output.printInfo("        if (j >= key_len) {{\n", .{});
        try output.printInfo("            j = 0;\n", .{});
        try output.printInfo("        }}\n", .{});
        try output.printInfo("    }}\n", .{});
        try output.printInfo("}}\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("pub fn main() !void {{\n", .{});
        try output.printInfo("    var ciphertext = XOR_CIPHERTEXT;\n", .{});
        try output.printInfo("    xorDecryption(&ciphertext, &XOR_KEY);\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode length: {{}}\\n\", .{{ciphertext.len}});\n", .{});
        try output.printInfo("    std.debug.print(\"Decrypted shellcode: {{any}}\\n\", .{{ciphertext}});\n", .{});
        try output.printInfo("\n", .{});
        try output.printInfo("    // Optional: Execute the shellcode (cross-platform example)\n", .{});
        try output.printInfo("    // const builtin = @import(\"builtin\");\n", .{});
        try output.printInfo("    // if (builtin.os.tag == .windows) {{\n", .{});
        try output.printInfo("    //     const windows = std.os.windows;\n", .{});
        try output.printInfo("    //     const exec_mem = windows.VirtualAlloc(\n", .{});
        try output.printInfo("    //         null,\n", .{});
        try output.printInfo("    //         ciphertext.len,\n", .{});
        try output.printInfo("    //         windows.MEM_COMMIT | windows.MEM_RESERVE,\n", .{});
        try output.printInfo("    //         windows.PAGE_EXECUTE_READWRITE\n", .{});
        try output.printInfo("    //     );\n", .{});
        try output.printInfo("    //     if (exec_mem) |mem| {{\n", .{});
        try output.printInfo("    //         @memcpy(@as([*]u8, @ptrCast(mem))[0..ciphertext.len], ciphertext);\n", .{});
        try output.printInfo("    //         const func: *const fn() callconv(.C) void = @ptrCast(mem);\n", .{});
        try output.printInfo("    //         func();\n", .{});
        try output.printInfo("    //     }}\n", .{});
        try output.printInfo("    // }}\n", .{});
        try output.printInfo("}}\n", .{});
    } else {
        try output.printError("[!] Unsupported Type Entered: {s}\n", .{transform_type});
    }
}

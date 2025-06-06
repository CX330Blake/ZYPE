const std = @import("std");
const key_generator = @import("./key_generator.zig");
const output = @import("../io/output.zig");

pub const Methods = union(enum) {
    aes: AESConfig,
    xor: NormalEncryptionConfig,
    rc4: NormalEncryptionConfig,
    ipv4: ObfuscationConfig,
    ipv6: ObfuscationConfig,
    mac: ObfuscationConfig,
    uuid: ObfuscationConfig,
};

const AESConfig = struct {
    shellcode: []const u8,
    key: []const u8,
    iv: []const u8,
};

const NormalEncryptionConfig = struct {
    shellcode: []const u8,
    key: []const u8,
};

const ObfuscationConfig = struct {
    shellcode: []const u8,
};

pub fn setPayload(allocator: std.mem.Allocator, shellcode: []const u8, method_type: @typeInfo(Methods).@"union".tag_type.?) !Methods {
    // try output.printInfo("Setting up payload with method: {s}\n", .{@tagName(method_type)});
    // try output.printInfo("Original shellcode size: {} bytes\n", .{shellcode.len});

    switch (method_type) {
        .aes => {
            // Generate AES-256 key and IV
            const key = try key_generator.generateRandomKey(allocator, 32); // AES-256
            const iv = try key_generator.generateRandomKey(allocator, 16); // AES IV

            // Create a copy of shellcode for encryption
            const encrypted_shellcode = try allocator.dupe(u8, shellcode);

            // Encrypt the shellcode
            try aesEncrypt(encrypted_shellcode, key, iv);

            return Methods{ .aes = AESConfig{
                .shellcode = encrypted_shellcode,
                .key = key,
                .iv = iv,
            } };
        },

        .xor => {
            // Generate 16-byte XOR key
            const key = try key_generator.generateRandomKey(allocator, 16);

            // Create a copy of shellcode for encryption
            const encrypted_shellcode = try allocator.dupe(u8, shellcode);

            // Encrypt the shellcode
            xor(encrypted_shellcode, key);

            return Methods{ .xor = NormalEncryptionConfig{
                .shellcode = encrypted_shellcode,
                .key = key,
            } };
        },

        .rc4 => {
            // Generate 16-byte RC4 key - FIXED: use key_generator module
            const key = try key_generator.generateRandomKey(allocator, 16);

            // Create a copy of shellcode for encryption
            const encrypted_shellcode = try allocator.dupe(u8, shellcode);

            // Encrypt the shellcode
            rc4(encrypted_shellcode, key);

            return Methods{ .rc4 = NormalEncryptionConfig{
                .shellcode = encrypted_shellcode,
                .key = key,
            } };
        },

        .ipv4 => {
            // For IPv4 obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            return Methods{ .ipv4 = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },

        .ipv6 => {
            // For IPv6 obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            return Methods{ .ipv6 = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },

        .mac => {
            // For MAC obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            return Methods{ .mac = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },

        .uuid => {
            // For UUID obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            return Methods{ .uuid = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },
    }
}

// Helper function to clean up method resources
pub fn cleanupMethod(allocator: std.mem.Allocator, method: Methods) void {
    switch (method) {
        .aes => |config| {
            allocator.free(config.shellcode);
            allocator.free(config.key);
            allocator.free(config.iv);
        },
        .xor, .rc4 => |config| {
            allocator.free(config.shellcode);
            allocator.free(config.key);
        },
        .ipv4, .ipv6, .mac, .uuid => |config| {
            allocator.free(config.shellcode);
        },
    }
}

/// This is the second approach to encrypt the payload.
/// We use a multi-bytes key and iterate each byte as different
/// key in each iteration.
pub fn xor(shellcode: []u8, key: []const u8) void {
    const key_len = key.len;
    if (key_len == 0) return; // Division by zero

    var j: usize = 0;
    for (shellcode) |*byte| {
        byte.* = byte.* ^ key[j];
        j += 1;
        if (j >= key_len) {
            j = 0;
        }
    }
}

/// RC4 encryption/decryption
/// RC4 is symmetric, so the same function is used for both encrypt and decrypt
pub fn rc4(data: []u8, key: []const u8) void {
    if (key.len == 0) return;

    // Initialize S-box
    var s: [256]u8 = undefined;
    for (&s, 0..) |*byte, i| { // FIXED: Added & to s
        byte.* = @intCast(i);
    }

    // Key scheduling algorithm (KSA)
    var j: u8 = 0;
    for (0..256) |i| {
        j = j +% s[i] +% key[i % key.len];
        std.mem.swap(u8, &s[i], &s[j]);
    }

    // Pseudo-random generation algorithm (PRGA)
    var i: u8 = 0;
    j = 0;
    for (data) |*byte| {
        i = i +% 1;
        j = j +% s[i];
        std.mem.swap(u8, &s[i], &s[j]);
        const k = s[s[i] +% s[j]];
        byte.* ^= k;
    }
}
/// AES encryption using CTR mode
/// data: input data to encrypt (will be modified in-place)
/// key: AES key (must be 16 or 32 bytes for AES-128 or AES-256)
/// iv: initialization vector (must be 16 bytes)
pub fn aesEncrypt(data: []u8, key: []const u8, iv: []const u8) !void {
    if (iv.len != 16) return error.InvalidIVLength;

    switch (key.len) {
        16 => {
            const key_array: [16]u8 = key[0..16].*;
            const ctx = std.crypto.core.aes.Aes128.initEnc(key_array);
            try aesEncryptWithContext(data, ctx, iv);
        },
        32 => {
            const key_array: [32]u8 = key[0..32].*;
            const ctx = std.crypto.core.aes.Aes256.initEnc(key_array);
            try aesEncryptWithContext(data, ctx, iv);
        },
        else => return error.InvalidKeyLength,
    }
}

/// Generic AES encryption helper that works with any AES context
fn aesEncryptWithContext(data: []u8, ctx: anytype, iv: []const u8) !void {
    var counter: [16]u8 = undefined;
    @memcpy(&counter, iv);

    var offset: usize = 0;
    while (offset < data.len) {
        var keystream: [16]u8 = undefined;
        ctx.encrypt(&keystream, &counter);

        const block_size = @min(16, data.len - offset);
        for (0..block_size) |i| {
            data[offset + i] ^= keystream[i];
        }

        // Increment counter
        var carry: u16 = 1;
        var i: usize = 15;
        while (carry > 0 and i < 16) {
            carry += counter[i];
            counter[i] = @intCast(carry & 0xFF);
            carry >>= 8;
            if (i == 0) break;
            i -= 1;
        }

        offset += block_size;
    }
}
/// AES decryption using CTR mode
/// CTR mode encryption and decryption are the same operation
pub fn aesDecrypt(data: []u8, key: []const u8, iv: []const u8) !void {
    try aesEncrypt(data, key, iv);
}

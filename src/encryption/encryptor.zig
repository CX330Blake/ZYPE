const std = @import("std");
const key_generator = @import("./key_generator.zig");

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

pub fn setPayload(allocator: std.mem.Allocator, shellcode: []const u8, method_type: @typeInfo(Methods).Union.tag_type.?) !Methods {
    const print = std.debug.print;

    print("==========================================\n");
    print("Setting up payload with method: {s}\n", .{@tagName(method_type)});
    print("Original shellcode size: {} bytes\n", .{shellcode.len});

    switch (method_type) {
        .aes => {
            print("Configuring AES-256-CTR encryption...\n");

            // Generate AES-256 key and IV
            const key = try key_generator.generateRandomKey(allocator, 32); // AES-256
            const iv = try key_generator.generateRandomKey(allocator, 16); // AES IV

            // Create a copy of shellcode for encryption
            var encrypted_shellcode = try allocator.dupe(u8, shellcode);

            // Encrypt the shellcode
            try aesEncrypt(encrypted_shellcode, key, iv);

            print("✓ AES-256 encryption completed\n");
            print("Key (32 bytes): ");
            for (key) |byte| print("{:02X}", .{byte});
            print("\nIV (16 bytes): ");
            for (iv) |byte| print("{:02X}", .{byte});
            print("\nEncrypted payload size: {} bytes\n", .{encrypted_shellcode.len});

            return Methods{ .aes = AESConfig{
                .shellcode = encrypted_shellcode,
                .key = key,
                .iv = iv,
            } };
        },

        .xor => {
            print("Configuring XOR encryption...\n");

            // Generate 16-byte XOR key
            const key = try generateRandomKey(allocator, 16);

            // Create a copy of shellcode for encryption
            var encrypted_shellcode = try allocator.dupe(u8, shellcode);

            // Encrypt the shellcode
            xor(encrypted_shellcode, key);

            print("✓ XOR encryption completed\n");
            print("Key (16 bytes): ");
            for (key) |byte| print("{:02X}", .{byte});
            print("\nEncrypted payload size: {} bytes\n", .{encrypted_shellcode.len});

            return Methods{ .xor = NormalEncryptionConfig{
                .shellcode = encrypted_shellcode,
                .key = key,
            } };
        },

        .rc4 => {
            print("Configuring RC4 encryption...\n");

            // Generate 16-byte RC4 key
            const key = try generateRandomKey(allocator, 16);

            // Create a copy of shellcode for encryption
            var encrypted_shellcode = try allocator.dupe(u8, shellcode);

            // Encrypt the shellcode
            rc4(encrypted_shellcode, key);

            print("✓ RC4 encryption completed\n");
            print("Key (16 bytes): ");
            for (key) |byte| print("{:02X}", .{byte});
            print("\nEncrypted payload size: {} bytes\n", .{encrypted_shellcode.len});

            return Methods{ .rc4 = NormalEncryptionConfig{
                .shellcode = encrypted_shellcode,
                .key = key,
            } };
        },

        .ipv4 => {
            print("Configuring IPv4 address obfuscation...\n");

            // For IPv4 obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            const ipv4_addresses = (shellcode.len + 3) / 4; // 4 bytes per IPv4
            print("✓ IPv4 obfuscation configured\n");
            print("Shellcode will be transformed into {} IPv4 addresses\n", .{ipv4_addresses});
            print("Format: xxx.xxx.xxx.xxx (4 bytes per address)\n");

            return Methods{ .ipv4 = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },

        .ipv6 => {
            print("Configuring IPv6 address obfuscation...\n");

            // For IPv6 obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            const ipv6_addresses = (shellcode.len + 15) / 16; // 16 bytes per IPv6
            print("✓ IPv6 obfuscation configured\n");
            print("Shellcode will be transformed into {} IPv6 addresses\n", .{ipv6_addresses});
            print("Format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx (16 bytes per address)\n");

            return Methods{ .ipv6 = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },

        .mac => {
            print("Configuring MAC address obfuscation...\n");

            // For MAC obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            const mac_addresses = (shellcode.len + 5) / 6; // 6 bytes per MAC
            print("✓ MAC address obfuscation configured\n");
            print("Shellcode will be transformed into {} MAC addresses\n", .{mac_addresses});
            print("Format: xx:xx:xx:xx:xx:xx (6 bytes per address)\n");

            return Methods{ .mac = ObfuscationConfig{
                .shellcode = shellcode_copy,
            } };
        },

        .uuid => {
            print("Configuring UUID obfuscation...\n");

            // For UUID obfuscation, store the original shellcode
            const shellcode_copy = try allocator.dupe(u8, shellcode);

            const uuid_count = (shellcode.len + 15) / 16; // 16 bytes per UUID
            print("✓ UUID obfuscation configured\n");
            print("Shellcode will be transformed into {} UUIDs\n", .{uuid_count});
            print("Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (16 bytes per UUID)\n");

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
    for (s, 0..) |*byte, i| {
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
/// key: AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
/// iv: initialization vector (must be 16 bytes)
pub fn aesEncrypt(data: []u8, key: []const u8, iv: []const u8) !void {
    if (iv.len != 16) return error.InvalidIVLength;

    const aes = switch (key.len) {
        16 => std.crypto.core.aes.Aes128,
        24 => std.crypto.core.aes.Aes192,
        32 => std.crypto.core.aes.Aes256,
        else => return error.InvalidKeyLength,
    };

    const ctx = aes.initEnc(key);
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

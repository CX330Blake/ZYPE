const std = @import("std");
const input = @import("io/input.zig");
const output = @import("io/output.zig");
const gpa = std.heap.GeneralPurposeAllocator(.{});
const banner = output.banner;

const key_generator = @import("encryption/key_generator.zig");
const encryptor = @import("encryption/encryptor.zig");
const obfuscator = @import("obfuscation/obfuscator.zig");
const Methods = encryptor.Methods;

fn generateArrayString(allocator: std.mem.Allocator, method: Methods) ![]u8 {
    var array_string = std.ArrayList(u8).init(allocator);
    defer array_string.deinit();

    switch (method) {
        .aes => |config| {
            // Generate AES arrays
            try array_string.appendSlice("const AES_KEY: [32]u8 = [_]u8{\n    ");
            for (config.key, 0..) |byte, i| {
                if (i > 0 and i % 16 == 0) try array_string.appendSlice("\n    ");
                try array_string.writer().print("0x{x:0>2}", .{byte});
                if (i < config.key.len - 1) try array_string.appendSlice(", ");
            }
            try array_string.appendSlice("\n};\n\n");

            try array_string.appendSlice("const AES_IV: [16]u8 = [_]u8{\n    ");
            for (config.iv, 0..) |byte, i| {
                if (i > 0 and i % 16 == 0) try array_string.appendSlice("\n    ");
                try array_string.writer().print("0x{x:0>2}", .{byte});
                if (i < config.iv.len - 1) try array_string.appendSlice(", ");
            }
            try array_string.appendSlice("\n};\n\n");

            try array_string.writer().print("const AES_CIPHERTEXT: [{}]u8 = [_]u8{{\n    ", .{config.shellcode.len});
            for (config.shellcode, 0..) |byte, i| {
                if (i > 0 and i % 16 == 0) try array_string.appendSlice("\n    ");
                try array_string.writer().print("0x{x:0>2}", .{byte});
                if (i < config.shellcode.len - 1) try array_string.appendSlice(", ");
            }
            try array_string.appendSlice("\n};\n");
        },
        .xor, .rc4 => |config| {
            const prefix = if (std.meta.activeTag(method) == .xor) "XOR" else "RC4";

            try array_string.writer().print("const {s}_KEY: [{}]u8 = [_]u8{{\n    ", .{ prefix, config.key.len });
            for (config.key, 0..) |byte, i| {
                if (i > 0 and i % 16 == 0) try array_string.appendSlice("\n    ");
                try array_string.writer().print("0x{x:0>2}", .{byte});
                if (i < config.key.len - 1) try array_string.appendSlice(", ");
            }
            try array_string.appendSlice("\n};\n\n");

            try array_string.writer().print("const {s}_CIPHERTEXT: [{}]u8 = [_]u8{{\n    ", .{ prefix, config.shellcode.len });
            for (config.shellcode, 0..) |byte, i| {
                if (i > 0 and i % 16 == 0) try array_string.appendSlice("\n    ");
                try array_string.writer().print("0x{x:0>2}", .{byte});
                if (i < config.shellcode.len - 1) try array_string.appendSlice(", ");
            }
            try array_string.appendSlice("\n};\n");
        },
        .ipv4 => |config| {
            // Use the obfuscator module for IPv4
            _ = try obfuscator.generateIpv4Output(allocator, config.shellcode);
            // Return empty string since output is handled by obfuscator
            return allocator.dupe(u8, "");
        },
        .ipv6 => |config| {
            // Use the obfuscator module for IPv6
            _ = try obfuscator.generateIpv6Output(allocator, config.shellcode);
            // Return empty string since output is handled by obfuscator
            return allocator.dupe(u8, "");
        },
        .mac => |config| {
            // Use the obfuscator module for MAC
            _ = try obfuscator.generateMacOutput(allocator, config.shellcode);
            // Return empty string since output is handled by obfuscator
            return allocator.dupe(u8, "");
        },
        .uuid => |config| {
            // Use the obfuscator module for UUID
            _ = try obfuscator.generateUuidOutput(allocator, config.shellcode);
            // Return empty string since output is handled by obfuscator
            return allocator.dupe(u8, "");
        },
    }

    return allocator.dupe(u8, array_string.items);
}

fn getArraySize(method: Methods) usize {
    return switch (method) {
        .aes, .xor, .rc4 => 1, // Not applicable for encryption methods
        .ipv4 => |config| (config.shellcode.len + 3) / 4,
        .ipv6 => |config| (config.shellcode.len + 15) / 16,
        .mac => |config| (config.shellcode.len + 5) / 6,
        .uuid => |config| (config.shellcode.len + 15) / 16,
    };
}

// Core processing function - can be used for both interactive and non-interactive modes
fn processShellcode(allocator: std.mem.Allocator, shellcode: []const u8, method_tag: std.meta.Tag(Methods)) !void {
    // Create encrypted shellcode copy
    const encrypted_shellcode = try allocator.dupe(u8, shellcode);
    defer allocator.free(encrypted_shellcode);

    // Generate method configuration based on type
    const method = switch (method_tag) {
        .xor => blk: {
            // Generate XOR key and encrypt directly
            const key = try key_generator.generateRandomKey(allocator, 16);
            defer allocator.free(key);

            // Call XOR encryption function directly from encryptor
            encryptor.xorEncrypt(encrypted_shellcode, key);

            // Create a persistent key copy for the method
            const key_copy = try allocator.dupe(u8, key);
            const shellcode_copy = try allocator.dupe(u8, encrypted_shellcode);

            break :blk Methods{ .xor = .{
                .shellcode = shellcode_copy,
                .key = key_copy,
            } };
        },
        .rc4 => blk: {
            // Generate RC4 key and encrypt directly
            const key = try key_generator.generateRandomKey(allocator, 16);
            defer allocator.free(key);

            // Call RC4 encryption function directly from encryptor
            encryptor.rc4Encrypt(encrypted_shellcode, key);

            // Create a persistent key copy for the method
            const key_copy = try allocator.dupe(u8, key);
            const shellcode_copy = try allocator.dupe(u8, encrypted_shellcode);

            break :blk Methods{ .rc4 = .{
                .shellcode = shellcode_copy,
                .key = key_copy,
            } };
        },
        .aes => blk: {
            // Generate AES key and IV, then encrypt directly
            const key = try key_generator.generateRandomKey(allocator, 32); // AES-256
            defer allocator.free(key);
            const iv = try key_generator.generateRandomKey(allocator, 16);
            defer allocator.free(iv);

            // Call AES encryption function directly from encryptor
            try encryptor.aesEncrypt(encrypted_shellcode, key, iv);

            // Create persistent copies for the method
            const key_copy = try allocator.dupe(u8, key);
            const iv_copy = try allocator.dupe(u8, iv);
            const shellcode_copy = try allocator.dupe(u8, encrypted_shellcode);

            break :blk Methods{ .aes = .{
                .shellcode = shellcode_copy,
                .key = key_copy,
                .iv = iv_copy,
            } };
        },
        // For obfuscation methods, use original setPayload approach
        else => try encryptor.setPayload(allocator, shellcode, method_tag),
    };

    defer encryptor.cleanupMethod(allocator, method);

    // Generate the array string for the output
    const array_str = try generateArrayString(allocator, method);
    defer allocator.free(array_str);

    const array_size = getArraySize(method);

    // For obfuscation methods, the output is already printed by the obfuscator functions
    // For encryption methods, we need to print the decoder functionality
    switch (method_tag) {
        // encryption - direct function calls
        .aes, .xor, .rc4 => {
            // Generate and print the decoder functionality for encryption methods
            try output.printDecodeFunctionality(@tagName(method_tag), array_str, array_size);
        },
        // obfuscation
        .ipv4, .ipv6, .mac, .uuid => {
            // For obfuscation methods, just print the decoder functionality without array_str
            // since the arrays are already printed by the obfuscator functions
            try output.printDecodeFunctionality(@tagName(method_tag), "", array_size);
        },
    }
}

// Helper function to parse method from string
fn parseMethodFromString(method_str: []const u8) ?std.meta.Tag(Methods) {
    if (std.ascii.eqlIgnoreCase(method_str, "aes")) return .aes;
    if (std.ascii.eqlIgnoreCase(method_str, "xor")) return .xor;
    if (std.ascii.eqlIgnoreCase(method_str, "rc4")) return .rc4;
    if (std.ascii.eqlIgnoreCase(method_str, "ipv4")) return .ipv4;
    if (std.ascii.eqlIgnoreCase(method_str, "ipv6")) return .ipv6;
    if (std.ascii.eqlIgnoreCase(method_str, "mac")) return .mac;
    if (std.ascii.eqlIgnoreCase(method_str, "uuid")) return .uuid;

    return null;
}

fn interactive() !void {
    var gpa_instance = gpa{};
    defer _ = gpa_instance.deinit();
    const allocator = gpa_instance.allocator();

    var buffer: [256]u8 = undefined;

    while (true) {
        try output.printMenu();

        if (try input.readMethod(&buffer)) |selected_index| {
            if (input.getMethodTag(selected_index)) |method_tag| {
                try output.printSuccess("You selected: {s}\n", .{@tagName(method_tag)});

                if (try input.readFile(allocator)) |shellcode| {
                    defer allocator.free(shellcode);
                    try processShellcode(allocator, shellcode, method_tag);
                    break;
                } else {
                    try output.printError("Failed to load shellcode file. Please try again.\n", .{});
                }
            } else {
                try output.printInfo("Invalid selection. Please choose a number between 0 and {}.\n", .{@typeInfo(std.meta.Tag(Methods)).@"enum".fields.len - 1});
            }
        } else {
            try output.printInfo("Invalid input. Please enter a number.\n", .{});
        }
    }
}

fn nonInteractive(method_str: []const u8, file_path: []const u8) !void {
    var gpa_instance = gpa{};
    defer _ = gpa_instance.deinit();
    const allocator = gpa_instance.allocator();

    // Parse method
    const method_tag = parseMethodFromString(method_str) orelse {
        try output.printError("Invalid method: {s}\n", .{method_str});
        try output.printError("Valid methods: aes, xor, rc4, ipv4, ipv6, mac, uuid\n", .{});
        return;
    };

    // Read shellcode file
    const shellcode = std.fs.cwd().readFileAlloc(allocator, file_path, 10 * 1024 * 1024) catch |err| {
        switch (err) {
            error.FileNotFound => {
                try output.printError("Error: File not found: {s}\n", .{file_path});
            },
            error.AccessDenied => {
                try output.printError("Error: Access denied: {s}\n", .{file_path});
            },
            error.IsDir => {
                try output.printError("Error: Path is a directory: {s}\n", .{file_path});
            },
            error.FileTooBig => {
                try output.printError("Error: File too large (max 10MB): {s}\n", .{file_path});
            },
            else => {
                try output.printError("Error: Cannot read file: {s} - {}\n", .{ file_path, err });
            },
        }
        return;
    };
    defer allocator.free(shellcode);

    if (shellcode.len == 0) {
        try output.printError("Error: File is empty: {s}\n", .{file_path});
        return;
    }

    // Process the shellcode
    try processShellcode(allocator, shellcode, method_tag);
}

pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        try output.printUsage();
        return;
    }

    var i: usize = 1;
    var method_str: ?[]const u8 = null;
    var file_path: ?[]const u8 = null;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interactive")) {
            try interactive();
            return;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try output.printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            try output.printVersion();
            return;
        } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--method")) {
            if (i + 1 < args.len) {
                i += 1;
                method_str = args[i];
            } else {
                try output.printError("Error: -m/--method requires a method name\n", .{});
                return;
            }
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
            if (i + 1 < args.len) {
                i += 1;
                file_path = args[i];
            } else {
                try output.printError("Error: -f/--file requires a file path\n", .{});
                return;
            }
        } else {
            try output.printError("Unknown option: {s}\n", .{arg});
            return;
        }
    }

    // If both method and file are provided, run non-interactive mode
    if (method_str != null and file_path != null) {
        try nonInteractive(method_str.?, file_path.?);
    } else if (method_str != null or file_path != null) {
        try output.printError("Error: Both -m/--method and -f/--file are required for non-interactive mode\n", .{});
        try output.printUsage();
    } else {
        try output.printUsage();
    }
}

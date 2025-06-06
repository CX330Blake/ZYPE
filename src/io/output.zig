const std = @import("std");
const stdout = std.io.getStdOut().writer();
const build_options = @import("build_options");
const version = build_options.version_string;

const menu = @import("../menu/menu.zig");
const Methods = menu.Methods;

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
        \\ZYPE v{s} - Shellcode encryptor
        \\
        \\Usage: zyra [options] <FILE>
        \\
        \\Options:
        \\  -h, --help           Show this help message
        \\  -i, --interactive    Interactive mode
        \\  -o, --output FILE    Output file name (default: input.zyra)
        \\  -k, --key HEX        Encryption key in hex (default: 0x42)
        \\
        \\Examples:
        \\  zyra /bin/ls                    # Pack ls -> ls.zyra
        \\  zyra -o myapp.exe program       # Pack program -> myapp.exe
        \\  zyra -k FF -v /usr/bin/cat      # Pack with key 0xFF, verbose
        \\
    , .{version});
}

pub fn printMenu() !void {
    const MethodsTag = @typeInfo(Methods).Union.tag_type.?;
    const method_tag_names = @typeInfo(MethodsTag).Enum.fields;

    try printVersion();

    comptime var i = 0;
    try printInfo("Choose the encryption/obfuscation method: (input the number)\n\n", .{});
    inline while (i < method_tag_names.len) : (i += 1) {
        if (i % 2 == 0) {
            try printInfo("({}) {s} \t", .{ i, method_tag_names[i].name });
        } else {
            try printInfo("({}) {s}\n", .{ i, method_tag_names[i].name });
        }
    }
    try printInfo("\n\n> ", .{});
}

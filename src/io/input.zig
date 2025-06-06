const std = @import("std");
const stdin = std.io.getStdIn().reader();
const Methods = @import("../encryption/encryptor.zig").Methods;
const output = @import("output.zig");

pub fn readFile(allocator: std.mem.Allocator) !?[]u8 {
    // Prompt user for shellcode file path
    try output.printInfo("Enter shellcode file path: ", .{});

    // Read file path from user input
    var buffer: [512]u8 = undefined;
    if (try stdin.readUntilDelimiterOrEof(&buffer, '\n')) |input| {
        const trimmed_path = std.mem.trim(u8, input, " \t\n\r");

        if (trimmed_path.len == 0) {
            try output.printError("Error: Empty path provided\n", .{});
            return null;
        }

        // Try to read the file
        const shellcode = std.fs.cwd().readFileAlloc(allocator, trimmed_path, 10 * 1024 * 1024) catch |err| {
            switch (err) {
                error.FileNotFound => {
                    try output.printError("Error: File not found: {s}\n", .{trimmed_path});
                },
                error.AccessDenied => {
                    try output.printError("Error: Access denied: {s}\n", .{trimmed_path});
                },
                error.IsDir => {
                    try output.printError("Error: Path is a directory: {s}\n", .{trimmed_path});
                },
                error.FileTooBig => {
                    try output.printError("Error: File too large (max 10MB): {s}\n", .{trimmed_path});
                },
                else => {
                    try output.printError("Error: Cannot read file: {s} - {}\n", .{ trimmed_path, err });
                },
            }
            return null;
        };

        if (shellcode.len == 0) {
            try output.printInfo("Warning: File is empty: {s}\n", .{trimmed_path});
            allocator.free(shellcode);
            return null;
        }

        return shellcode;
    }

    return null;
}

pub fn readMethod(buffer: []u8) !?usize {
    if (try stdin.readUntilDelimiterOrEof(buffer, '\n')) |input| {
        const trimmed_input = std.mem.trim(u8, input, " \t\n\r");

        if (std.fmt.parseInt(usize, trimmed_input, 10)) |index| {
            const MethodsTag = @typeInfo(Methods).@"union".tag_type.?;
            const method_tag_names = @typeInfo(MethodsTag).@"enum".fields;

            if (index < method_tag_names.len) {
                return index;
            }
        } else |_| {
            // Invalid input
        }
    }
    return null;
}

pub fn getMethodTag(index: usize) ?@typeInfo(Methods).@"union".tag_type.? {
    const MethodsTag = @typeInfo(Methods).@"union".tag_type.?;
    const method_tag_names = @typeInfo(MethodsTag).@"enum".fields;

    if (index >= method_tag_names.len) {
        return null;
    }

    return @enumFromInt(index);
}

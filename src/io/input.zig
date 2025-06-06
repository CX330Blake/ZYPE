const std = @import("std");
const stdin = std.io.getStdIn().reader();
const menu = @import("../menu/menu.zig");
const Methods = menu.Methods;

pub fn readFile(allocator: std.mem.Allocator) !?[]u8 {
    const stdout = std.io.getStdOut().writer();

    // Prompt user for shellcode file path
    try stdout.print("Enter shellcode file path: ");

    // Read file path from user input
    var buffer: [512]u8 = undefined;
    if (try stdin.readUntilDelimiterOrEof(&buffer, '\n')) |input| {
        const trimmed_path = std.mem.trim(u8, input, " \t\n\r");

        if (trimmed_path.len == 0) {
            try stdout.print("Error: Empty path provided\n");
            return null;
        }

        // Try to read the file
        const shellcode = std.fs.cwd().readFileAlloc(allocator, trimmed_path, 10 * 1024 * 1024) catch |err| {
            switch (err) {
                error.FileNotFound => {
                    try stdout.print("Error: File not found: {s}\n", .{trimmed_path});
                },
                error.AccessDenied => {
                    try stdout.print("Error: Access denied: {s}\n", .{trimmed_path});
                },
                error.IsDir => {
                    try stdout.print("Error: Path is a directory: {s}\n", .{trimmed_path});
                },
                error.FileTooBig => {
                    try stdout.print("Error: File too large (max 10MB): {s}\n", .{trimmed_path});
                },
                else => {
                    try stdout.print("Error: Cannot read file: {s} - {}\n", .{ trimmed_path, err });
                },
            }
            return null;
        };

        if (shellcode.len == 0) {
            try stdout.print("Warning: File is empty: {s}\n", .{trimmed_path});
            allocator.free(shellcode);
            return null;
        }

        try stdout.print("Successfully loaded shellcode: {} bytes from {s}\n", .{ shellcode.len, trimmed_path });
        return shellcode;
    }

    return null;
}

pub fn readMethod(buffer: []u8) !?usize {
    if (try stdin.readUntilDelimiterOrEof(buffer, '\n')) |input| {
        const trimmed_input = std.mem.trim(u8, input, " \t\n\r");

        if (std.fmt.parseInt(usize, trimmed_input, 10)) |index| {
            const MethodsTag = @typeInfo(Methods).Union.tag_type.?;
            const method_tag_names = @typeInfo(MethodsTag).Enum.fields;

            if (index < method_tag_names.len) {
                return index;
            }
        } else |_| {
            // Invalid input
        }
    }
    return null;
}

pub fn getMethodTag(index: usize) ?@typeInfo(Methods).Union.tag_type.? {
    const MethodsTag = @typeInfo(Methods).Union.tag_type.?;
    const method_tag_names = @typeInfo(MethodsTag).Enum.fields;

    if (index >= method_tag_names.len) {
        return null;
    }

    return @enumFromInt(index);
}

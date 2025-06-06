const std = @import("std");
const input = @import("./io/input.zig");
const output = @import("./io/output.zig");
const gpa = std.heap.GeneralPurposeAllocator();
const banner = output.banner;

const chosen_method: Methods = undefined;

const key_generator = @import("encryption/key_generator.zig");
const encryptor = @import("encryption/encryptor.zig");
const Methods = encryptor.Methods;

fn setPayload() !void {}

fn interactive() !void {
    var buffer: [256]u8 = undefined;

    while (true) {
        try output.printMenu();

        if (try input.readMethod(&buffer)) |selected_index| {
            if (input.getMethodTag(selected_index)) |method_tag| {
                try output.printInfo("You selected: {s}\n", .{@tagName(method_tag)});

                var shellcode = try input.readFile(gpa);

                // Handle the selected method
                switch (method_tag) {
                    .aes => {
                        try output.printInfo("AES encryption selected\n", .{});
                        break; // Exit the loop
                    },
                    .xor => {
                        try output.printInfo("XOR encryption selected\n", .{});
                        break;
                    },
                    .rc4 => {
                        try output.printInfo("RC4 encryption selected\n", .{});
                        break;
                    },
                    .ipv4 => {
                        try output.printInfo("IPv4 obfuscation selected\n", .{});
                        break;
                    },
                    .ipv6 => {
                        try output.printInfo("IPv6 obfuscation selected\n", .{});
                        break;
                    },
                    .mac => {
                        try output.printInfo("MAC obfuscation selected\n", .{});
                        break;
                    },
                    .uuid => {
                        try output.printInfo("UUID obfuscation selected\n", .{});
                        break;
                    },
                }
            } else {
                try output.printInfo("Invalid selection. Please choose a number between 0 and {}.\n", .{@typeInfo(@typeInfo(Methods).Union.tag_type.?).Enum.fields.len - 1});
            }
        } else {
            try output.printInfo("Invalid input. Please enter a number.\n", .{});
        }
    }
}

pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        try output.printUsage();
        return;
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-i") or (std.mem.eql(u8, arg, "--interactive"))) {
            try interactive();
        } else if (std.mem.eql(u8, arg, "-h") or (std.mem.eql(u8, arg, "--help"))) {
            try output.printUsage();
        } else if (std.mem.eql(u8, arg, "-v") or (std.mem.eql(u8, arg, "--version"))) {
            try output.printVersion();
        } else if (std.mem.eql(u8, arg, "-f") or (std.mem.eql(u8, arg, "--file"))) {
            var shellcode = try input.readFile(gpa);
            try setPayload(shellcode);
        } else {
            try output.printError("Unknown option: {s}\n", .{arg});
        }
    }
}

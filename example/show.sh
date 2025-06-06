../zig-out/bin/ZYPE -f shellcode.bin -m aes >aes.zig
../zig-out/bin/ZYPE -f shellcode.bin -m rc4 >rc4.zig
../zig-out/bin/ZYPE -f shellcode.bin -m xor >xor.zig
../zig-out/bin/ZYPE -f shellcode.bin -m ipv4 >ipv4.zig
../zig-out/bin/ZYPE -f shellcode.bin -m ipv6 >ipv6.zig
../zig-out/bin/ZYPE -f shellcode.bin -m mac >mac.zig
../zig-out/bin/ZYPE -f shellcode.bin -m uuid >uuid.zig

zig build-exe aes.zig
zig build-exe rc4.zig
zig build-exe xor.zig
zig build-exe ipv4.zig
zig build-exe ipv6.zig
zig build-exe mac.zig
zig build-exe uuid.zig

./aes
./rc4
./xor
./ipv4
./ipv6
./mac
./uuid

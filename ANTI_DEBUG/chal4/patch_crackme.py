from pwn import *
crackme = ELF("./crackme-origin.enc")
patch_list = [
(0x1800 , 0x45c748fffff84be8),
(0x1871 , 0x89e0458b48000000),
(0x18e5 , 0x1ebfffff7b5e8c7),
(0x1838 , 0x8948d8458b48c289),
(0x18a8 , 0x775fff883fffffd),

(0x16db , 0xe8c78948000009ab),
(0x174b , 0x8348008b48d8458b),
(0x17bd , 0x1ebfffff93de8c7),
(0x1712 , 0xe8c7894800000000),
(0x1781 , 0xf975e8c78948f845),

(0x16db , 0xbbbdda32537a5ad1),
(0x174b , 0xd33150f218a115f2),
(0x17bd , 0x5093ae87a845b9bf),
(0x1712 , 0xdddbbc54351c351c),
(0x1781 , 0x7fda6e680fe77eea),

(0x140b , 0xc700000000f845c7),
(0x1494 , 0xbaf0458b1c7501f8),
(0x151f , 0x1eb9004ebffffff),
(0x144f , 0xbe0fef458800b60f),
(0x14d7 , 0xf44539c0b60f1004),

(0x13b9 , 0xb04a5b749d359b75),
(0x13bd , 0x28c197b658b3b38d),
(0x13c4 , 0x1ebfc4589ffc1d0),
(0x13ba , 0x3bc43e2f0001b807),
(0x13be , 0xffffffb805eb0000),

(0x13b9 , 0x83eb83ea3becf6),
(0x13bd , 0x177f5085e8030303),
(0x13c4 , 0xe86a15c4607e1696),
(0x13ba , 0x80d8ee68e0fb609),
(0x13be , 0x28c04106365bb0b0),

(0x13b9 , 0xb0335b0de435e275),
(0x13bd , 0x28c1eeb658b3b38d),
(0x13c4 , 0x1ebfc4589ffc1a9),
(0x13ba , 0x3bbd3e560001b807),
(0x13be , 0xffffffb805eb0000),

(0x13b9 , 0xb0385b06ef35e975),
(0x13bd , 0x28c1e5b658b3b38d),
(0x13c4 , 0x1ebfc4589ffc1a2),
(0x13ba , 0x3bb63e5d0001b807),
(0x13be , 0xffffffb805eb0000),

(0x13b9 , 0x88eb88ea30ecfd),
(0x13bd , 0x1774508ee8030303),
(0x13c4 , 0xe86115cf6075169d),
(0x13ba , 0x3068eed8e04bd02),
(0x13be , 0x28c04a0d3d5bb0b0),

(0x13b9 , 0xb0385b06ef35e975),
(0x13bd , 0x28c1e5b658b3b38d),
(0x13c4 , 0x1ebfc4589ffc1a2),
(0x13ba , 0x3bb63e5d0001b807),
(0x13be , 0xffffffb805eb0000),

(0x13b9 , 0x91eb91ea29ece4),
(0x13bd , 0x176d5097e8030303),
(0x13c4 , 0xe87815d6606c1684),
(0x13ba , 0x1a1f8ef48e1da41b),
(0x13be , 0x28c05314245bb0b0),

(0x140b , 0x8448434843b0068f),
(0x1494 , 0xfabb05c05c3e41b3),
(0x151f , 0x40a1d14eaab5beb5),
(0x144f , 0x9b21ca6bad2e9321),
(0x14d7 , 0x62d8af5d20928699),

(0x1373 , 0x17e27f613f63871),
(0x1376 , 0x1ebfc453a63b257),
(0x1372 , 0x89d001e4458bc289),

(0x1372 , 0xcf9f47ab03c484c6),
(0x1373 , 0x83da0bee4f81c8),
(0x1376 , 0x45a6b84dc7974fa3),
(0x1372 , 0xe7be6f8a6fa8e8ef),
(0x1372 , 0x7424fc10fc327b75),

(0x1372 , 0x326bba5fba7d3d3a),
(0x1373 , 0x87e2ef61af63871),
(0x1376 , 0x1ebfc453a63b257),
(0x1372 , 0x1a4a927ed6115113),
(0x1372 , 0x89d001e4458bc289),

(0x1372 , 0xcf8447b003df84dd),
(0x1373 , 0x98c110f5549ad3),
(0x1376 , 0x45bdb856dc9754a3),
(0x1372 , 0xfca5749174a8f3ef),
(0x1372 , 0x6f24e710e729606e),
        ]

a_patch_list = [
(0x1372 , 0x88d100e500ce8789),
(0x1373 , 0x1cd9445a0458bc2),
(0x1376 , 0x1ebfc4589d001e4),
(0x1372 , 0xa9f021c465abe2a9),
(0x1372 , 0x3a63b257f638713a)
        ]

patch_int3 = [
(0x17DC, 0x17f9),
(0x16b7, 0x16d4),
(0x13e7, 0x1404),
(0x17c6, 0x17cb),
(0x1399, 0x13b2),
(0x13cd, 0x13d2),
(0x1528, 0x152d),
(0x1352, 0x136b),
(0x137f, 0x1384)
#(0x16B7, 0x90)
]
ls = []
for rip, opcode in patch_list:
    
    if not rip in ls:
        ls.append(rip)
        crackme.write(rip, p64(opcode))
#for rip, opcode in a_patch_list:
#    crackme.write(rip, p64(opcode))


for st, ed in patch_int3:
    for i in range(st, ed):
        crackme.write(i, b"\x90")

#for i in ls:
#    crackme.write(i, b"\x90")


#for rip, opcode in patch_int3:
#    crackme.write(rip, bytes([opcode]))
#for rip in range(0x17dc, 0x17fa):
#    crackme.write(rip, bytes([0x90]))
#for rip in range(0x16b7, 0x16d5):
#    crackme.write(rip, bytes([0x90]))
#


crackme.save("./crackme.enc")


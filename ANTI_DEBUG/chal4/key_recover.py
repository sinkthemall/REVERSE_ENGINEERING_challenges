box = b'\x1bY)L=o"\x7f&\x1c,/\x07N\x17\x1ea\nS\x104eJBX\x08\x1d`3U7DR9.r\x0fn~?2GZ\x13\x19\x06zQ\x18\x1acH\x02w>T5\x16\x04^OI0\x03\x15qM\x118\x12\x05E\'h:u\t \x01@i#j;A_{W<\x1ffV\\\x0c6s-gC]K(vx}1m%\x14t[k\rPpd\x0eb+\x0bF*|yl$!\xff'
pair = []

def trace_back(val):
    msg = ''
    while val:
        if val % 2:
            msg += '0'
            val = (val - 1)//2
        else:
            msg += '1'
            val = (val - 2)//2
    return msg[::-1]

for i in range(1, 0x7f + 1):
    for j in range(len(box)):
        if box[j] == i:
            pair.append((i, j))

ans = ""

for i, j in pair:
    msg = trace_back(j)
    ans += msg 
    ans += "?"

print(ans)

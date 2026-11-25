"""Restricted structural decoder for synthetic CLR method-body byte strings."""
import struct

class InvalidIL(ValueError):
    pass

def check(ok, reason):
    if not ok:
        raise InvalidIL(reason)

# Explicit supported subset; unknown instructions fail closed.
# Operand encodings: u1, i1, u2, i4, i8, r4, r8, token, br1, br4, switch.
OPS = {x:("none",0) for x in (
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,
    0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x25,0x26,0x2a,
    0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,
    0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,
    0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
    0x76,0x7a,0x8e,0xdc,0xdf,0xe0,0xfe01,0xfe02,0xfe03,0xfe04,0xfe05,
    0xfe0f,0xfe11,0xfe17,0xfe18,0xfe1a,0xfe1d)}
for x in range(0x0e,0x14): OPS[x]=("u1",1)
OPS.update({0x1f:("i1",1),0x20:("i4",4),0x21:("i8",8),0x22:("r4",4),0x23:("r8",8),
            0x45:("switch",0),0xdd:("br4",4),0xde:("br1",1)})
for x in range(0x2b,0x38): OPS[x]=("br1",1)
for x in range(0x38,0x45): OPS[x]=("br4",4)
for x in (0x27,0x28,0x29,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x79,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x8c,0x8d,0x8f,0xa3,0xa4,0xa5,0xc2,0xc6,0xd0,0xfe06,0xfe07,0xfe15,0xfe1c):
    OPS[x]=("token",4)
for x in range(0xfe09,0xfe0f): OPS[x]=("u2",2)

def read_u(data, pos, size):
    check(0 <= pos <= len(data)-size, "truncated field")
    return int.from_bytes(data[pos:pos+size],"little")

def decode(code):
    pos=0
    instructions=[]
    targets=[]
    while pos<len(code):
        start=pos
        op=code[pos]; pos+=1
        if op==0xfe:
            check(pos<len(code),"truncated two-byte opcode")
            op=0xfe00|code[pos]; pos+=1
        check(op in OPS,"unsupported opcode")
        kind,width=OPS[op]
        if kind=="switch":
            count=read_u(code,pos,4)
            check(count <= (len(code)-pos-4)//4,"truncated switch")
            width=4+count*4
        check(pos+width<=len(code),"truncated operand")
        raw=code[pos:pos+width]; pos+=width
        if kind in ("br1","br4"):
            targets.append(pos+int.from_bytes(raw,"little",signed=True))
        elif kind=="switch":
            for n in range(count):
                targets.append(pos+int.from_bytes(raw[4+n*4:8+n*4],"little",signed=True))
        elif kind=="token":
            check(int.from_bytes(raw,"little") & 0xffffff != 0,"nil operand token")
        instructions.append({"offset":start,"opcode":op,"operand":raw.hex(),"kind":kind})
    boundaries={i["offset"] for i in instructions}
    check(bool(boundaries),"empty method")
    check(all(t in boundaries for t in targets),"branch target not instruction boundary")
    return instructions,boundaries

def parse(body):
    check(isinstance(body,bytes) and 0<len(body)<=67108864,"body size")
    flags=body[0]&3
    if flags==2:
        start=1; size=body[0]>>2; more=False; local=0; maxstack=8
        form="tiny"
    elif flags==3:
        word=read_u(body,0,2)
        check(word>>12==3 and word & 0xfff & ~0x1b == 0,"unsupported fat header")
        start=12; maxstack=read_u(body,2,2); size=read_u(body,4,4)
        local=read_u(body,8,4); more=bool(word&8); form="fat"
        check(local==0 or (local>>24==0x11 and local&0xffffff!=0),"local signature token")
    else:
        raise InvalidIL("invalid method header")
    end=start+size
    check(size>0 and end<=len(body),"code size")
    instructions,bounds=decode(body[start:end])
    clauses=[]
    if more:
        pos=(end+3)&~3
        check(pos<=len(body) and not any(body[end:pos]),"section padding")
        while True:
            check(pos+4<=len(body),"missing EH section")
            kind=body[pos]; fat=bool(kind&0x40); continuation=bool(kind&0x80)
            check(kind&0x3f==1,"unsupported section")
            section_size=read_u(body,pos+1,3 if fat else 1)
            if not fat: check(body[pos+2:pos+4]==b"\x00\x00","small EH reserved bytes")
            width=24 if fat else 12
            check(section_size>=4+width and (section_size-4)%width==0 and pos+section_size<=len(body),"EH section size")
            for q in range(pos+4,pos+section_size,width):
                if fat:
                    flag,to,tl,ho,hl,value=struct.unpack_from("<6I",body,q)
                else:
                    flag,to,tl,ho,hl,value=struct.unpack_from("<HHB H B I",body,q)
                check(flag in (0,1,2,4),"unsupported EH flag")
                check(tl>0 and hl>0 and to in bounds and ho in bounds and to+tl in bounds|{size} and ho+hl in bounds|{size},"EH range")
                check(to+tl<=ho or ho+hl<=to,"overlapping try/handler")
                if flag==0: check(value>>24 in (1,2,27) and value&0xffffff!=0,"catch token")
                elif flag==1: check(value in bounds and value<ho,"filter offset")
                else: check(value==0,"nonzero reserved EH payload")
                clauses.append({"flags":flag,"try_offset":to,"try_length":tl,"handler_offset":ho,"handler_length":hl,"value":value})
            end=pos+section_size
            if not continuation: break
            pos=(end+3)&~3
            check(pos<=len(body) and not any(body[end:pos]),"section padding")
    check(end==len(body),"unconsumed body bytes")
    return {"format":form,"code_size":size,"max_stack":maxstack,"local_sig":local,
            "instructions":instructions,"exception_clauses":clauses}

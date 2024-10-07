import capstone
import struct
from pprint import pprint


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
# a=md.disasm(open(target, "rb").read()[elf.getsectionbyname(".text").sh.offset:], elf.getsectionbyname(".text").sh.offset, elf.getsectionbyname(".text").sh.size)

__all__ = [
    "set_offset",
    "get_rel_target"
]


def encode(value: int, size: int):
    if value > 0:
        return value.to_bytes(size, "little")
    
    return struct.pack("<"+{
        1:"b",
        2:"h",
        4:"i",
        8:"q",
    }[size], value)

def decode(target: bytes, size: int):
    return struct.unpack("<"+{
        1:"b",
        2:"h",
        4:"i",
        8:"q",
    }[size], target)

def set_offset_generic(instruction: capstone.CsInsn, operand: int, new_offset: int):
    instruction_bytes = instruction.bytes

    disp_size = instruction.disp_size
    if (1<<(8*disp_size)) <= new_offset:
        print(f"INVALID {disp_size=}, attempting to manualy corect for {instruction.disp=}")

        disp_size = 2 if (1<< 8) <= new_offset else disp_size
        disp_size = 4 if (1<<16) <= new_offset else disp_size
        disp_size = 8 if (1<<32) <= new_offset else disp_size

        print(f"\t{instruction.disp_size} => {disp_size}", "\n", flush=True)
        assert instruction.bytes[instruction.disp_offset: instruction.disp_offset + disp_size]

    new_instruction_bytes = instruction_bytes[:instruction.disp_offset] \
            + encode(new_offset, disp_size) \
            + instruction_bytes[instruction.disp_offset + disp_size:]

    assert 1 == len(list(md.disasm(new_instruction_bytes, instruction.address)))
    new_instruction = list(md.disasm(new_instruction_bytes, instruction.address))[0]
    assert new_instruction.operands[operand].mem.disp == new_offset
    
    return new_instruction

def set_rel_call(instruction: capstone.CsInsn, operand: int, new_target: int):
    instruction_bytes = instruction.bytes

    imm_size = instruction.imm_size
    # if (1<<(8*disp_size)) <= new_offset:
    #     print(f"INVALID {disp_size=}, attempting to manualy corect for {instruction.disp=}")

    #     disp_size = 2 if (1<< 8) <= new_offset else disp_size
    #     disp_size = 4 if (1<<16) <= new_offset else disp_size
    #     disp_size = 8 if (1<<32) <= new_offset else disp_size

    #     print(f"\t{instruction.disp_size} => {disp_size}", "\n", flush=True)
    #     assert instruction.bytes[instruction.disp_offset: instruction.disp_offset + disp_size]

    new_offset = new_target - instruction.address - instruction.size 
    new_instruction_bytes = instruction_bytes[:instruction.imm_offset] \
            + encode(new_offset, imm_size) \
            + instruction_bytes[instruction.imm_offset + imm_size:]

    assert 1 == len(list(md.disasm(new_instruction_bytes, instruction.address)))
    new_instruction = list(md.disasm(new_instruction_bytes, instruction.address))[0]
    assert new_instruction.operands[operand].imm == new_target

    # return new_instruction
    return new_instruction

helpers = {
    # capstone.x86.X86_INS_MOV: set_offset_generic,
}

helpers_rel = {
    capstone.x86.X86_INS_CALL: set_rel_call,
    # capstone.x86.X86_INS_MOV: set_offset_generic,
}

def set_offset(instruction: capstone.CsInsn, operand:int, new_offset: int) -> capstone.CsInsn:
    if instruction.id in helpers:
        return helpers[instruction.id](instruction, operand, new_offset)

    return set_offset_generic(instruction, operand, new_offset)

def set_rel_target(instruction: capstone.CsInsn, operand: int, new_target: int) -> capstone.CsInsn:

    return helpers_rel[instruction.id](instruction, operand, new_target)
    return instruction
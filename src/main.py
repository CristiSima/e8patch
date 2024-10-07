import subprocess
import argparse
import pathlib
import shutil
import json
import os
import elfesteem.elf_init as ei
import elfesteem.elf as e
import capstone
import logging

import patch_elfesteem

from pathlib import Path
from struct import pack, unpack
from pprint import pprint
from change_instruction_offset import set_offset, set_rel_target
from address_translator import *
from itertools import chain
from dataclasses import dataclass, field
from logging import getLogger

logging.basicConfig(
    level=logging.WARNING,
    format="%(lineno)03d: %(msg)s",
)

NLT = "\n\t"
target = r"F:\container\mnt\RoCSC-Final\pwn\main"
target = r"F:\container\mnt\test\Licenta\test"
# target = r"F:\container\mnt\test\Licenta\test_s"
# target = r"F:\container\mnt\test\Licenta\test_fr"
target_no_plt = r"F:\container\mnt\test\Licenta\test_fr2"
addition_file = r"F:\container\mnt\test\Licenta\added.o"
patch_file = r"F:\container\mnt\test\Licenta\added.c"
compiled_patch_no_plt = r"F:\container\mnt\test\Licenta\added_no_pie.o"
# target=r"R:\bin\ls"

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

ignored_instructions = set()

@dataclass
class FakeSymbol:
    name: str
    value: int

@dataclass
class ReplaceCommand:
    target: str
    ref_to_old: str
    new_implementation: str

    def from_pragma(line: str) -> 'ReplaceCommand':
        ref_to_old = new_implementation = None

        pragma, replace, target, args = line.strip().split(" ", 3)

        for arg in args.split(" "):
            assert arg[3] in ":="
            if arg.startswith("old"):
                ref_to_old = arg[4:]
            elif arg.startswith("new"):
                new_implementation = arg[4:]
            else:
                raise Exception(f"unknown [{arg[:3]}]")

        return ReplaceCommand(
            target,
            ref_to_old,
            new_implementation
        )

@dataclass
class PatchInfo:
    target_path: Path
    patch_path: Path

    compiled_patch_path: Path = field(kw_only=True, default=None)

    symbols_path: Path = field(kw_only=True, default=None)

    # symbols added to the newly created executable
    imported_symbols: list[str] = field(init=False, default_factory=list)

    # ex: a libc function not used in the original executable
    new_external_functions: list[str] = field(init=False, default_factory=list)

    external_full_name: dict[str, str] = field(init=False, default_factory=dict)

    reference_replacements: dict[str, str] = field(init=False, default_factory=dict)
    virtual_reference: dict[str, str] = field(init=False, default_factory=dict)

    section_append_offset: dict[str, int] = field(init=False, default_factory=dict)
    section_append_index: dict[str, int] = field(init=False, default_factory=dict)

    unmodified_target: ei.ELF = field(init=False)

    target: ei.ELF = field(init=False)
    patch: ei.ELF = field(init=False)

    translator: Address_Translator = field(init=False, default=None)

    virtual_symbols: dict[str, FakeSymbol] = field(init=False, default=None)

    @property
    def symbols(self) -> e.Sym64 | FakeSymbol:
        return self.virtual_symbols or self.target.symbols.symbols

    @property
    def is_full_RELRO(self) -> bool:
        # RELRO is not part of the spec but a concept
        # using full-RELRO involves the usage of BIND_NOW as a flag in the dynamic section
        # PT_GNU_RELRO	 	
        #     The array element specifies the location and size of a segment which may be made read-only after relocation shave been processed
        if self.target.getsectionbyname(".dynamic").get_with_type(e.DT_FLAGS) is None:
            return False

        return self.target.getsectionbyname(".dynamic").get_with_type(e.DT_FLAGS).name_idx & e.DF_BIND_NOW > 0

    @property
    def has_plt(self) -> bool:
        '''PLT is optional even if preferable
        the tramboline (.plt section) can be removed and in it's place all calls to externall function will directly jump to the address in GOT
        this forces the loader to perform all dynamic resolution before giving execution to the program
        '''
        return self.target.getsectionbyname(".dynamic").get_with_type(e.DT_JMPREL) is not None

    def __post_init__(self):
        assert self.patch_path.suffix == ".c"

        self.unmodified_target = ei.ELF(open(self.target_path, "rb").read())
        self.target = ei.ELF(open(self.target_path, "rb").read())

        if not self.compiled_patch_path:
            self.compiled_patch_path = self.patch_path.parent / f"{self.patch_path.stem}.o"

            extra_args = []

            if not self.has_plt:
                extra_args.append("-fno-plt")
                
            if os.name == "posix":
                result = subprocess.run([
                        "gcc",
                        str(self.patch_path),
                        "-c",
                        "-o", str(self.compiled_patch_path),
                        # TODO: -O0 and -fno-stack-protector could be removed 
                        # O0: guarantes insertions
                        # stack_check_fail might not be present
                        *"-O0 -fno-stack-protector -Wall -Wno-unknown-pragmas".split(" "),
                        *extra_args
                    ],
                    capture_output=True
                )

                if result.returncode:
                    print(f"Patch compilation failed with RC: [{result.returncode}]")
                    print("STDOUT:")
                    print(result.stdout.decode())
                    print("STDERR:")
                    print(result.stderr.decode())
                    exit(3)

            assert os.path.isfile(self.compiled_patch_path)

        self.patch = ei.ELF(open(self.compiled_patch_path, "rb").read())

        if not self.target.getsectionbyname(".symtab"):
            self.extract_target_symbols()
        else:
            if self.symbols_path:
                raise Exception("Ignoring symbols file")

    def extract_target_symbols(self):
        self.virtual_symbols: dict[str, FakeSymbol] = {}

        if not self.symbols_path:
            parser.error("A symbols file is requiered when patching a stripped executable")

        try:
            symbols = json.load(open(self.symbols_path))
        except json.JSONDecodeError as err:
            print(err)
            parser.error(f"Json error when parsing symbols file, [{err.msg}]")

        if "symbols" not in symbols or type(symbols["symbols"]) is not dict:
            parser.error(f"Invalid syntax: .symbols should be a dictonary")

        for name, address in symbols["symbols"].items():
            if type(address) is str:
                if not address.startswith("0x"):
                    parser.error(f"Invalid syntax: string value should be a hex string. ['{name}':{address}]")

                try:
                    address = int(address[2:], 16)
                except ValueError:
                    parser.error(f"Invalid syntax: string value should be a hex string. ['{name}':{address}]")

            elif type(address) is not int:
                parser.error(f"Invalid syntax: value should be int or hex string. ['{name}':{address}]")
            
            self.virtual_symbols[name] = FakeSymbol(name, address)

    def get_libc_version(self) -> str:
        # https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html
        # TODO better logic
        # requiers an external function import
        if self.has_plt:
            external_func_dyn_symbol_index = self.target.getsectionbyname(".rela.plt").reltab[0].sym_idx
        else:
            itr = filter(lambda x:x.type == e.R_X86_64_GLOB_DAT, self.target.getsectionbyname(".rela.dyn").reltab)
            next(itr),next(itr)
            external_func_dyn_symbol_index = next(itr).sym_idx

            while self.target.getsectionbyname(".gnu.version").indexes[external_func_dyn_symbol_index] <= 1:
                external_func_dyn_symbol_index = next(itr).sym_idx
        
        external_func_ver_index = self.target.getsectionbyname(".gnu.version").indexes[external_func_dyn_symbol_index]
            
        for ver_aux in self.target.getsectionbyname(".gnu.version_r").auxs:
            if ver_aux.vna_other & 0x7FFF == external_func_ver_index:
                return ver_aux.name

        raise Exception("Failed to deduce libc version")

    def get_libc_index_for_version(self, version: str):
        # https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html
        assert self.target.getsectionbyname(".gnu.version_r")
        
        for e in self.target.getsectionbyname(".gnu.version_r").auxs:
            if e.name == version:
                return e.vna_other & 0x7FFF

        raise Exception("Failed to get version identifier")

    def extract_patch_instructions(self):
        plt_function_target_lib = self.get_libc_version()

        unknown_symbols = []
        self.imported_symbols = [
            sym.name for sym in self.patch.symbols
            if sym.type in ["FUNC", "OBJECT"]
        ]
        undefined_symbols = [
            sym.name for sym in self.patch.symbols
            if sym.type == "NOTYPE" and sym.bind == "GLOBAL"
        ]

        self.parse_patch()

        # categorize patch symbols 
        for undefined_symbol in undefined_symbols:
            # skip references to existing symbols
            if undefined_symbol in (self.virtual_symbols or self.unmodified_target.symbols.symbols):
                continue

            if undefined_symbol in self.virtual_reference:
                continue

            if undefined_symbol in [
                        "_GLOBAL_OFFSET_TABLE_",
                    ]:
                continue
            # can be
            # 1) an existing external symbol, it's entry in the global symbol table has it's name appended with the lib name and version  system@GLIBC_2.2.5
            # 2) an external symbol not present, the PLT needs to be expanded acordingly
            # 3) a typo

            #  !!!  ASUMPTION !!!
            # typos will be cought by the compiler
            # TODO: maybe add some check for 3

            for exiting_symbol in (self.virtual_symbols or self.unmodified_target.symbols.symbols):
                if exiting_symbol.startswith(undefined_symbol):
                    self.external_full_name[undefined_symbol] = exiting_symbol
                    break
            else:
                # TODO: use proper logic to determine a version
                self.new_external_functions.append(undefined_symbol)
                self.external_full_name[undefined_symbol] = f"{undefined_symbol}@{plt_function_target_lib}"

                print(f"DID NOT FOUND symbol '{undefined_symbol}' present, importing it")

        # add remaining external symbols        
        for exiting_symbol in (self.virtual_symbols or self.unmodified_target.symbols.symbols):
            if "@" not in exiting_symbol or exiting_symbol in self.external_full_name.values():
                continue

            self.external_full_name[exiting_symbol.split("@")[0]] = exiting_symbol

        for target, symb in list(self.reference_replacements.items()):
            if target not in self.external_full_name:
                continue

            self.reference_replacements[self.external_full_name[target]] = symb

        return

    def parse_patch(self):
        for line in open(self.patch_path):
            if not line.startswith("#pragma"):
                continue

            if line.startswith("#pragma replace"):
                command = ReplaceCommand.from_pragma(line)

                if command.ref_to_old:
                    self.virtual_reference[command.ref_to_old] = command.target

                self.reference_replacements[command.target] = command.new_implementation
            else:
                # TODO: there are valid pragmas, these must be handled
                raise Exception(f"Unknown pragma [{line.split(' ',1)[1]}]")

    def get_plt_address(self, symbol_name: str):
        local_logger = getLogger("get_plt_address")
        # local_logger.setLevel(logging.DEBUG)

        rela: ei.RelATable = self.target.getsectionbyname(".rela.plt") or self.target.getsectionbyname(".rela.dyn")
        assert rela

        local_logger.debug([rela.name for rela in rela.reltab])
        rela: e.Rela64 = [rela for rela in rela.reltab if rela.name.startswith(symbol_name)][0]

        local_logger.debug(f"{rela.offset = :x}")
        local_logger.debug(f"{self.target.getsectionbyname('.got.plt')} -> {self.target.getsectionbyname('.got.plt').addr:x} {self.target.getsectionbyname('.got.plt').size:x}")
        local_logger.debug(f"{self.target.ph.phlist[5].addr:x}, {self.target.ph.phlist[5].size:x} -> {self.target.ph.phlist[5].addr + self.target.ph.phlist[5].size:x}")

        if self.has_plt:
            plt_addr = unpack("Q", self.target.virt(rela.offset, rela.offset+8))[0]

            return (plt_addr | 0x0F) ^ 0x0F

        return rela.offset

def get_symbol_at_addr(self: PatchInfo, address: int):
    for symbol in self.symbols.values():
        if symbol.value == address:
            return symbol

    plt_sec: ei.Section = self.target.getsectionbyname(".plt")
    if self.has_plt and plt_sec.addr <= address <= plt_sec.addr + plt_sec.size:
        for rela in self.target.getsectionbyname(".rela.plt").reltab:
            rela: e.Rela64
            if address == self.get_plt_address(rela.name):
                return rela.symbol
    
    return None


def disassemble_section(pi: PatchInfo, section_name: str):
    target_section = pi.target.getsectionbyname(section_name)
    if not target_section:
        return []
        
    # use original size to allow the use of Section.append_section_content
    original_size = pi.unmodified_target.getsectionbyname(section_name).sh.size

    return md.disasm(
        target_section.content[:original_size],
        target_section.sh.offset,
        original_size
    )

def check_elf_section_assumsions(target):
    local_logger = getLogger("check_elf_section_assumsions")
    # local_logger.setLevel(logging.DEBUG)
    elf = ei.ELF(open(target,"rb").read())

    for section_header in elf.sh:
        if section_header.phparent:
            continue

        if isinstance(section_header, ei.NullSection) or \
                section_header.name == ".comment" or \
                section_header.addr == 0:
            # ignore section that shouldn't have a parent
            continue
        local_logger.error(section_header)
        raise Exception("Section without parent")

    for segment_header in elf.ph:
        for section_header in segment_header.shlist_partial:
            if not section_header.phparent:
                raise Exception("Partial section without parent")

    # TODO: if this fails more logic needs to be added to add new entries to the appropriate sections
    if elf.getsectionbyname(".dynamic").get_with_type(e.DT_JMPREL) is not None or elf.getsectionbyname(".rela.plt"):
        assert elf.getsectionbyname(".dynamic").get_with_type(e.DT_JMPREL).name_idx == elf.getsectionbyname(".rela.plt").addr
    assert elf.getsectionbyname(".dynamic").get_with_type(e.DT_SYMTAB).name_idx == elf.getsectionbyname(".dynsym").addr

PLT_TRAMBULINE_SIZE = 0x10
GOTPLT_ENTRY_SIZE = 8
GNU_VERSYM_ENTRY_SIZE = 2


def expand_sections(self: PatchInfo):
    local_logger = getLogger("expand_sections")
    # local_logger.setLevel(logging.DEBUG)

    self.target.getsectionbyname(".symtab")

    self.section_append_offset[".text"] = self.unmodified_target.getsectionbyname(".text").size
    self.target.getsectionbyname(".text").append_section_content(self.patch.getsectionbyname(".text"))

    if not self.virtual_symbols:
        sym_entry_size = self.target.getsectionbyname(".symtab").sh.entsize
        self.section_append_index[".symtab"] = len(self.unmodified_target.getsectionbyname(".symtab"))
        self.target.getsectionbyname(".symtab").resize(0, sym_entry_size * (len(self.imported_symbols) + len(self.new_external_functions)))

        self.section_append_offset[".strtab"] = self.unmodified_target.getsectionbyname(".strtab").size
        # functions in plt must also have a symbol
        self.target.getsectionbyname(".strtab").resize(
            0,
            sum(len(new_symbol_name)+1 for new_symbol_name in self.imported_symbols)
            + sum(len(self.external_full_name[new_plt_function_symbol])+1 for new_plt_function_symbol in self.new_external_functions)
        )

    if self.has_plt:
        relaplt_entry_size = self.unmodified_target.getsectionbyname(".rela.plt").sh.entsize
        self.section_append_index[".rela.plt"] = len(self.unmodified_target.getsectionbyname(".rela.plt").reltab)
        self.target.getsectionbyname(".rela.plt").resize(0, relaplt_entry_size*len(self.new_external_functions))
    else:
        reladyn_entry_size = self.unmodified_target.getsectionbyname(".rela.dyn").sh.entsize
        self.section_append_index[".rela.dyn"] = len(self.unmodified_target.getsectionbyname(".rela.dyn").reltab)
        self.target.getsectionbyname(".rela.dyn").resize(0, reladyn_entry_size*len(self.new_external_functions))

    dynsym_entry_size = self.unmodified_target.getsectionbyname(".dynsym").sh.entsize
    self.section_append_index[".dynsym"] = len(self.unmodified_target.getsectionbyname(".dynsym"))
    self.target.getsectionbyname(".dynsym").resize(0, dynsym_entry_size*len(self.new_external_functions))

    self.section_append_offset[".dynstr"] = self.unmodified_target.getsectionbyname(".dynstr").size
    self.target.getsectionbyname(".dynstr").resize(0, sum(len(new_symbol_name)+1 for new_symbol_name in self.new_external_functions))

    local_logger.debug(self.target.sections.readelf_display())

    if self.target.getsectionbyname(".gnu.version"):
        # GNU compiler specific
        self.section_append_index[".gnu.version"] = len(self.unmodified_target.getsectionbyname(".gnu.version"))
        self.target.getsectionbyname(".gnu.version").resize(0, 2 * len(self.new_external_functions))

    local_logger.debug(self.target.sections.readelf_display())

    if self.has_plt:
        self.section_append_offset[".plt"] = self.unmodified_target.getsectionbyname(".plt").size
        self.target.getsectionbyname(".plt").resize(0, len(self.new_external_functions) * PLT_TRAMBULINE_SIZE)

    if self.is_full_RELRO:
        self.section_append_offset[".got"] = self.unmodified_target.getsectionbyname(".got").size
        self.target.getsectionbyname(".got").resize(0, GOTPLT_ENTRY_SIZE*len(self.new_external_functions))
    else:
        self.section_append_offset[".got.plt"] = self.unmodified_target.getsectionbyname(".got.plt").size
        self.target.getsectionbyname(".got.plt").resize(0, GOTPLT_ENTRY_SIZE*len(self.new_external_functions))

    local_logger.debug(self.target.sections.readelf_display())

    if self.patch.getsectionbyname(".data") and self.patch.getsectionbyname(".data").size:
        self.section_append_offset[".data"] = self.unmodified_target.getsectionbyname(".data").size
        self.target.getsectionbyname(".data").append_section_content(self.patch.getsectionbyname(".data"))

    local_logger.debug(self.target.sections.readelf_display())

    if self.patch.getsectionbyname(".rodata") and self.patch.getsectionbyname(".rodata").size:
        self.section_append_offset[".rodata"] = self.unmodified_target.getsectionbyname(".rodata").size
        self.target.getsectionbyname(".rodata").append_section_content(self.patch.getsectionbyname(".rodata"))

    local_logger.debug(self.target.sections.readelf_display())

    if self.patch.getsectionbyname(".bss") and self.patch.getsectionbyname(".bss").size:
        self.section_append_offset[".bss"] = self.unmodified_target.getsectionbyname(".bss").size
        
        # since .bss is of type NOBITS, it doesn't ocupy space in the file and is directly fallowed by the next section
        # self.target.getsectionbyname(".bss").resize(0, self.patch.getsectionbyname(".bss").size)
        self.target.getsectionbyname(".bss").sh.size += self.patch.getsectionbyname(".bss").size
        self.target.getsectionbyname(".bss").phparent.ph.memsz += self.patch.getsectionbyname(".bss").size

    self.target.check_coherency()

    local_logger.debug(self.target.sections.readelf_display())
    for sec in self.target.sections:
        local_logger.debug(f"{sec}\t\t{sec.sh.offset:x} -> {sec.sh.offset+sec.size:x}\n\t{sec.next_section()}")

    for section in self.target.sections.shlist:
        section.fix_allignment_requierments()
        local_logger.debug("\n\n\n" + self.target.sections.readelf_display())
        try:
            self.target.check_coherency()
        except Exception  as e:
            local_logger.debug("\t allignment BROKEN")
        else:
            local_logger.debug("\tallignment OK")

    for sec in self.target.sections:
        local_logger.debug(f"{sec}\t\t{sec.sh.offset:x} -> {sec.sh.offset+sec.size:x}\n\t {sec.next_section()}")

    self.target.check_coherency()
    calc_address_translation(self)
    post_expansion_fixes(self)
    self.target.build_content()

    local_logger.debug(self.target.sections.readelf_display())
    self.target.check_coherency()


def post_expansion_fixes(self: PatchInfo):
    self.target.getsectionbyname(".dynamic").recalc()

    self.target.build_content()
    self.target.check_coherency()

    # update exception handle header segment addres to match section addr
    if self.target.getsectionbyname(".eh_frame_hdr"):
        for ph in self.target.ph.phlist:
            if ph.ph.type == e.PT_GNU_EH_FRAME:
                ph.ph.offset = self.target.getsectionbyname(".eh_frame_hdr").sh.offset
                ph.ph.paddr = ph.ph.offset = ph.ph.vaddr = self.target.getsectionbyname(".eh_frame_hdr").addr
    else:
        raise Exception("How did I get here?")

    self.target.getsectionbyname(".dynsym").translate(self.translator)
    self.target.getsectionbyname(".rela.dyn").translate(self.translator)

    if self.target.getsectionbyname(".rela.plt"):
        self.target.getsectionbyname(".rela.plt").translate(self.translator)

    if self.target.getsectionbyname(".symtab"):
        self.target.getsectionbyname(".symtab").translate(self.translator)
    else:
        for symbol in self.virtual_symbols.values():
            symbol.value = self.translator.translate_address(symbol.value)

    self.target.Ehdr.entry = self.translator.translate_address(self.target.entrypoint)

    self.target.build_content()
    self.target.check_coherency()

    post_resize_update_code(self)


# # manual fix bc of my bad code
# symb: ei.SymTable = elf.getsectionbyname(".symtab")
# if not symb:
#     raise Exception("NO symbol section found, I think I kind of need this for relocations")
# fini_symbol: ei.elf.Sym64 = symb.symbols["_fini"]
# fini_symbol.value = elf.getsectionbyname(".fini").addr
# # fini_symbol.value = translator.translate(fini_symbol.value)
# symb[fini_symbol.idx] = fini_symbol



def post_resize_update_relative_branch(self: PatchInfo, section_name: str, target_section: ei.Section, instruction: capstone.CsInsn):
    offset: capstone.x86.X86Op = instruction.operands[0]
    assert len(instruction.operands) == 1
    local_logger = getLogger("post_resize_update_relative_branch")
    # local_logger.setLevel(logging.DEBUG)
    
    local_logger.debug(f"{instruction}, {offset.imm:x}, {instruction.address:x}, {self.translator.reverse_translation_address(instruction.address):x}")

    # for some reason .imm gives the target instead of the actual offset
    accessed_address = offset.imm + self.translator.reverse_translation_address(instruction.address) - instruction.address
    translated_accessed_address = self.translator.translate_address(accessed_address)

    if offset.imm == translated_accessed_address:
        # the resize doesn't change the offset, a fix is not necesary
        return True
    local_logger.debug(f"{instruction} {accessed_address:x} {translated_accessed_address:x}")

    new_ins = set_rel_target(instruction, 0, translated_accessed_address)

    target_section.content[
        instruction.address - target_section.addr:
        instruction.address + instruction.size - target_section.addr
    ] = new_ins.bytes

    local_logger.debug(f"replaced {instruction} => {new_ins}")

def post_resize_update_operand_mem_offset(self: PatchInfo, section_name: str, target_section: ei.Section, instruction: capstone.CsInsn, op_index: int, op:capstone.x86.X86OpValue):
    local_logger = getLogger("post_resize_update_operand_mem_offset")
    # local_logger.setLevel(logging.DEBUG)
    if not op.type == capstone.x86.X86_OP_MEM:
        return
    
    if op.mem.base in [
            capstone.x86.X86_REG_RSP,
            capstone.x86.X86_REG_RBP,
            ]:
        # ignore stack interaction
        return
    if op.mem.base not in [
            capstone.x86.X86_REG_RIP,
            capstone.x86.X86_REG_RSP,
            capstone.x86.X86_REG_RBP,
            ]:
        if all(e == 0 for e in instruction.bytes):
            # 0 bytes => padding
            return

        if bytes(instruction.bytes) in ignored_instructions:
            return

        ignored_instructions.add(bytes(instruction.bytes))

        local_logger.warning(f"Ignoring instruction: {instruction}\n\tposible source source of broken reference\n\t[post_resize_update_operand_mem_offset]\n")
        return

    local_logger.debug(f"{instruction} {op_index} {len(instruction.operands)} {op.mem.base}")
    assert op.mem.index == 0

    # instructions are dissasembles using the new section address
    original_instruction_address = self.translator.reverse_translation_address(instruction.address)
    # when the addres is calculated RIP points to the next instruction
    accessed_address = original_instruction_address + instruction.size + op.mem.disp
    translated_accessed_address = self.translator.translate_address(accessed_address)
    # reverse
    new_instruction_offset = translated_accessed_address - instruction.address - instruction.size

    # replace offset
    local_logger.debug(instruction)
    new_ins = set_offset(instruction, op_index, new_instruction_offset)
    local_logger.debug(new_ins)

    # overwrite instruction
    target_section.content[
        instruction.address - target_section.addr:
        instruction.address + instruction.size - target_section.addr
    ] = new_ins.bytes


def post_resize_update_code(self: PatchInfo):
    for section in [
                ".text",
                ".init",
                ".plt",
                ".fini",
            ]:
        disasm_generator = disassemble_section(self, section)
        target_section = self.target.getsectionbyname(section) 
        for instruction in disasm_generator:
            instruction: capstone.CsInsn
            if instruction.id == capstone.x86.X86_INS_NOP:
                continue
            
            if capstone.CS_GRP_BRANCH_RELATIVE in instruction.groups:
                post_resize_update_relative_branch(self, section, target_section, instruction)
                continue

            for op_index, op in enumerate(instruction.operands):
                post_resize_update_operand_mem_offset(self, section, target_section, instruction, op_index, op)

    self.target.build_content()
    self.target.check_coherency()

    self.target = ei.ELF(self.target.build_content())



def check_address_translation(self: PatchInfo):
    local_logger = getLogger("check_address_translation")
    # local_logger.setLevel(logging.DEBUG)

    for section in self.unmodified_target.sections:
        section: ei.Section
        local_logger.debug(section.name)
        new_section = self.target.getsectionbyname(section.name)
        for offset in range(section.size):
            try:
                assert self.translator.translate_address(section.addr + offset) == new_section.addr + offset
                assert self.translator.reverse_translation_address(new_section.addr + offset) == section.addr + offset
            except Exception as e:
                local_logger.error(f"{offset:x} {section}")
                local_logger.error(f"\tnew: {new_section}")
                local_logger.error(
                    f"{section.addr + offset:x} == [{self.translator.reverse_translation_address(new_section.addr + offset):x}] => " +
                    f"{new_section.addr + offset:x} == [{not self.translator.is_consumed_address(section.addr + offset) and self.translator.translate_address(section.addr + offset):x}]")
                local_logger.error(f"[\n\t{NLT.join(map(str,self.translator.address_insertions))}\n]")
                local_logger.error("")
                local_logger.error("New:")
                local_logger.error(self.target.sections.readelf_display())
                local_logger.error("")
                local_logger.error("Old:")
                local_logger.error(self.unmodified_target.sections.readelf_display())
                local_logger.error("")
                print(2)
                raise e
    local_logger.debug("[+] Address Translation is valid")
    

def calc_address_translation(self):
    translator = Address_Translator()
    insertions = Inserted_Memory_Regions()
    local_logger = getLogger("calc_address_translation")
    # local_logger.setLevel(logging.DEBUG)

    extra_space = 0
    local_logger.debug("\n\n\n" + self.target.sections.readelf_display())

    def in_page(address: int): return address % 0x1000

    for section in self.unmodified_target.sections:
        section: ei.Section
        new_section: ei.Section = self.target.getsectionbyname(section.name)

        next_section = section.next_section()
        if type(next_section) is list:
            next_section = next_section[0]

        new_next_section: ei.Section = self.target.getsectionbyname(next_section.name) if next_section else None

        local_logger.debug(f"ext {extra_space:x}")
        local_logger.debug(f"Old {section} -> {section.sh.offset + section.size:x}] {next_section}")
        local_logger.debug(f"New {new_section} -> {new_section.sh.offset + new_section.size:x}] {new_next_section}")

        # if section.sh.offset == new_section.sh.offset and section.size == new_section.size:
        #     continue

        if in_page(section.sh.offset) != in_page(new_section.sh.offset):
            diff = new_section.sh.offset - section.sh.offset - extra_space
            local_logger.debug(f"start location:\n\tdiff: {diff:x}")
            
            insertions.in_file_space.append(Inserted_Memory(section.sh.offset, diff))
            if section.addr:
                local_logger.debug(f"A {Inserted_Memory(section.addr, diff)}")
                insertions.in_addres_space.append(Inserted_Memory(section.addr, diff))

            extra_space += diff

        if section.size != new_section.size:
            diff = new_section.size - section.size
            local_logger.debug("expanded:\n\tdiff: {diff:x}")

            # remove the buffer between sections from the expansion
            # this may not be the way
            if next_section:
                old_diff = diff
                diff -= next_section.sh.offset - (section.sh.offset + section.size)
                diff = max(0, diff)
                local_logger.debug(f"\treuse {old_diff:x} => {diff:x}")


            insertions.in_file_space.append(Inserted_Memory(section.sh.offset + section.size, diff))
            if section.addr:
                local_logger.debug(f"B {Inserted_Memory(section.addr + section.size, diff)}")
                insertions.in_addres_space.append(Inserted_Memory(section.addr + section.size, diff))

            extra_space += diff
        
        # if next_section and next_section.phparent is not new_next_section.sh.offset and extra_space:
        if next_section and in_page(next_section.sh.offset) == in_page(new_next_section.sh.offset) and extra_space:
            # this might be where a segment should be expanded
            # print(f"{section.sh.offset = :x}")
            # print(f"{extra_space = :x}")
            # print(f"{new_next_section.sh.offset - next_section.sh.offset = :x}")
            new_extra_space = new_next_section.sh.offset - next_section.sh.offset
            diff = new_extra_space - extra_space
            # print(f"{diff = :x}")
            # assert extra_space == new_next_section.sh.offset - next_section.sh.offset
            # assert extra_space < 0x1000
            # assert next_section.sh.offset - section.sh.offset - section.size >= extra_space

            # TODO:

            local_logger.debug(f"[\n{NLT.join(map(str,insertions.in_file_space))}\n]")
            
            insertions.in_file_space.append(Inserted_Memory(section.sh.offset + section.size + 1, diff))
            if section.addr:
                local_logger.debug(f"C {Inserted_Memory(section.addr + section.size + 1, diff)}")
                insertions.in_addres_space.append(Inserted_Memory(section.addr + section.size + 1, diff))

            extra_space -= in_page(extra_space)
            extra_space = new_extra_space
            # extra_space = 0


    local_logger.debug(f"addres: [\n{NLT.join(map(str, insertions.in_addres_space))}\n]")
    local_logger.debug(f"file:   [\n{NLT.join(map(str, insertions.in_file_space))}\n]")
    
    translator.add_all_for_address(insertions.in_addres_space)
    translator.add_all_for_offset(insertions.in_file_space)

    self.translator = translator
    check_address_translation(self)


def add_dynamic(self: PatchInfo):
    dynstr: ei.StrTable = self.target.getsectionbyname(".dynstr")

    dynstr.content[self.section_append_offset[".dynstr"]: dynstr.size] = b"".join([
        new_symbol_name.encode() + b"\x00" for new_symbol_name in self.new_external_functions
    ])
    self.section_append_offset[".dynstr"] += sum(map(len, self.new_external_functions)) + len(self.new_external_functions)

    dynsymb: ei.SymTable = self.target.getsectionbyname(".dynsym")
    plt = self.target.getsectionbyname(".plt")
    relaplt: ei.RelATable = self.target.getsectionbyname(".rela.plt")
    reladyn: ei.RelATable = self.target.getsectionbyname(".rela.dyn")
    
    if not dynsymb:
        raise Exception("NO symbol section found, I think I kind of need this for relocations")

    if self.is_full_RELRO:
        got_section_name = ".got"
    else:
        got_section_name = ".got.plt"

    gotplt = self.target.getsectionbyname(got_section_name)


    for i, new_plt_function in enumerate(self.new_external_functions):
        # create symbol
        new_symbol = ei.elf.Sym64(dynsymb)

        new_symbol.name_idx = dynstr.find_name(new_plt_function)
        
        new_symbol.info = e.STT_FUNC | (e.STB_GLOBAL<<4)
        new_symbol.other = e.STV_DEFAULT
        new_symbol.size = 0
        new_symbol.value = 0

        new_symbol.shndx = e.SHN_UNDEF

        dynsymb[self.section_append_index[".dynsym"]] = new_symbol

        # create relocation entry
        if self.has_plt:
            new_rela = e.Rela64(relaplt)

            new_rela.offset = gotplt.addr + self.section_append_offset[got_section_name] 
            # TODO: why not R_X86_64_JUMP_SLOT?
            new_rela.info = (e.R_386_JMP_SLOT) | (self.section_append_index[".dynsym"] << 32)
            relaplt[self.section_append_index[".rela.plt"]] = new_rela

            # initialize got to trambuline resolver prep
            plt_trambuline_addr = plt.addr + self.section_append_offset[".plt"]
            gotplt.content[
                self.section_append_offset[got_section_name]:
                self.section_append_offset[got_section_name] + GOTPLT_ENTRY_SIZE
            ] = pack("i", plt_trambuline_addr + 6)

            # assemble trambuline instructions with appropriate offsets
            # jmp [gotplt_entry]
            # push identifier
            # jmp [plt_resolver]
            jmp_offset_to_gotplt_entry = new_rela.offset - (plt_trambuline_addr+6)
            jmp_offset_to_pre_resolver = plt.addr - (plt_trambuline_addr + 6+5+5)

            plt.content[
                self.section_append_offset[".plt"]:
                self.section_append_offset[".plt"] + PLT_TRAMBULINE_SIZE
            ] = b"\xFF\x25" + pack("i", jmp_offset_to_gotplt_entry) \
                + b"\x68" + pack("i", self.section_append_index[".rela.plt"]) \
                + b"\xe9" + pack("i", jmp_offset_to_pre_resolver)
        else:
            new_rela = e.Rela64(reladyn)

            new_rela.offset = gotplt.addr + self.section_append_offset[got_section_name] 
            new_rela.info = (e.R_X86_64_GLOB_DAT) | (self.section_append_index[".dynsym"] << 32)
            reladyn[self.section_append_index[".rela.dyn"]] = new_rela


        self.section_append_index[".dynsym"] += 1
        self.section_append_offset[got_section_name] += GOTPLT_ENTRY_SIZE
        if self.has_plt:
            self.section_append_index[".rela.plt"] += 1
            self.section_append_offset[".plt"] += PLT_TRAMBULINE_SIZE
        else:
            self.section_append_index[".rela.dyn"] += 1

    if self.target.getsectionbyname(".gnu.version"):
        # GNU compiler specific
        for i in range(self.section_append_index[".gnu.version"], len(self.target.getsectionbyname(".gnu.version"))):
            # TODO: use a proper version
            self.target.getsectionbyname(".gnu.version")[i] = self.get_libc_index_for_version(self.get_libc_version())


def add_program_symbols(self: PatchInfo):
    if self.virtual_symbols:
        for i, new_symbol_name in enumerate(self.imported_symbols):
            old_symbol: e.Sym64 = self.patch.getsectionbyname(".symtab")[new_symbol_name]

            original_section_name = self.patch.sections[old_symbol.shndx].name
            if original_section_name not in self.section_append_offset:
                raise Exception(f"Unknown section [{original_section_name}] for symbol {old_symbol}")

            base_addr = self.unmodified_target.getsectionbyname(original_section_name).size + self.target.getsectionbyname(original_section_name).addr

            self.virtual_symbols[new_symbol_name] = FakeSymbol(new_symbol_name, base_addr + old_symbol.value)

        # plt functions don't need to be added to virtual symbols since they are not present
        return

    symb: ei.SymTable = self.target.getsectionbyname(".symtab")
    strt: ei.StrTable = self.target.getsectionbyname(".strtab")

    assert strt and symb
    
    for new_symbol_name in self.imported_symbols:
        strt.content[
            self.section_append_offset[".strtab"]:
            self.section_append_offset[".strtab"] + len(new_symbol_name) + 1
        ] = new_symbol_name.encode() + b"\x00"

        self.section_append_offset[".strtab"] += len(new_symbol_name) + 1

    for i, new_symbol_name in enumerate(self.imported_symbols):
        new_symbol = ei.elf.Sym64(symb)

        old_symbol: e.Sym64 = self.patch.getsectionbyname(".symtab")[new_symbol_name]

        new_symbol.name_idx = strt.find_name(new_symbol_name)
        
        new_symbol.info = old_symbol.info
        new_symbol.other = old_symbol.other
        new_symbol.size = old_symbol.size

        original_section_name = self.patch.sections[old_symbol.shndx].name
        if original_section_name not in self.section_append_offset:
            raise Exception(f"Unknown section [{original_section_name}] for symbol {old_symbol}")

        new_symbol.shndx = self.target.sections.shlist.index(self.target.getsectionbyname(original_section_name))
        base_addr = self.unmodified_target.getsectionbyname(original_section_name).size + self.target.getsectionbyname(original_section_name).addr
        new_symbol.value = base_addr + old_symbol.value

        symb[self.section_append_index[".symtab"]] = new_symbol
        self.section_append_index[".symtab"] += 1

    # plt functions need to be present in both .dynsymb and .symtab
    for new_symbol_name in self.new_external_functions:
        full_name = self.external_full_name[new_symbol_name]
        strt.content[
            self.section_append_offset[".strtab"]:
            self.section_append_offset[".strtab"] + len(full_name) + 1
        ] = full_name.encode() + b"\x00"

        self.section_append_offset[".strtab"] += len(full_name) + 1

    # plt functions need to be present in both .dynsymb and .symtab
    for i, new_symbol_name in enumerate(self.new_external_functions):
        new_symbol = ei.elf.Sym64(symb)

        new_symbol.name_idx = strt.find_name(self.external_full_name[new_symbol_name])
        
        new_symbol.info = e.STT_FUNC | (e.STB_GLOBAL<<4)
        new_symbol.other = e.STV_DEFAULT
        new_symbol.size = 0
        new_symbol.value = 0
        new_symbol.shndx = e.SHN_UNDEF

        symb[self.section_append_index[".symtab"]] = new_symbol
        self.section_append_index[".symtab"] += 1

    self.target.build_content()
    self.target.check_coherency()

    assert self.section_append_offset[".strtab"] == strt.size


def replace_instruction_reference_offset_relative_branch(self: PatchInfo, text_section: ei.Section, instruction: capstone.CsInsn):
    assert len(instruction.operands) == 1
    local_logger = getLogger("replace_instruction_reference_offset_relative_branch")
    # local_logger.setLevel(logging.DEBUG)

    offset: capstone.x86.X86Op = instruction.operands[0]
    # for some reason imm gives the target/accessed address instead of the actual offset

    # get the symbol associated with the target address and check if it's replaced
    old_symbol: e.Sym64 = get_symbol_at_addr(self, offset.imm)
    local_logger.debug(f"{instruction}\n\t{old_symbol}")
    if old_symbol is None or old_symbol.name not in self.reference_replacements:
        return

    new_symbol: e.Sym64 = self.symbols[self.reference_replacements[old_symbol.name]]

    new_ins = set_rel_target(instruction, 0, new_symbol.value)

    # continue
    text_section.content[instruction.address-text_section.addr:instruction.address+instruction.size-text_section.addr] = new_ins.bytes
    local_logger.debug(f"replaced {instruction} => {new_ins}")
    
def replace_instruction_reference_operand_mem_offset(self: PatchInfo, text_section: ei.Section, instruction: capstone.CsInsn, op_index: int, op:capstone.x86.X86OpValue):
    local_logger = getLogger("replace_instruction_reference_operand_mem_offset")
    # local_logger.setLevel(logging.DEBUG)
    if op.mem.base in [
            capstone.x86.X86_REG_RSP,
            capstone.x86.X86_REG_RBP,
            ]:
        # ignore stack interaction
        return
    if op.mem.base not in [
            capstone.x86.X86_REG_RIP,
            capstone.x86.X86_REG_RSP,
            capstone.x86.X86_REG_RBP,
            ]:
        
        if all(e == 0 for e in instruction.bytes):
            # 0 bytes => padding
            return

        if bytes(instruction.bytes) in ignored_instructions:
            return

        ignored_instructions.add(bytes(instruction.bytes))

        local_logger.warning(f"Ignoring instruction: {instruction}\n\tposible source source of broken reference [replace_instruction_reference_operand_mem_offset]\n")
        return

    local_logger.debug(f"{instruction} {op_index} {len(instruction.operands)} {op.mem.base}")
    assert op.mem.index == 0

    # when the addres is calculated RIP points to the next instruction
    accessed_address = instruction.address + instruction.size + op.mem.disp
    accessed_address = instruction.address + instruction.size + op.mem.disp

    local_logger.debug(f"{instruction} {accessed_address:x}")

    old_symbol: e.Sym64 = get_symbol_at_addr(self, accessed_address)
    if old_symbol is None or old_symbol.name not in self.reference_replacements:
        return

    new_symbol: e.Sym64 = self.symbols[self.reference_replacements[old_symbol.name]]

    # reverse
    new_instruction_offset = new_symbol.value - instruction.address - instruction.size

    # replace offset
    new_ins = set_offset(instruction, op_index, new_instruction_offset)

    # overwrite instruction
    text_section.content[instruction.address-text_section.addr:instruction.address+instruction.size-text_section.addr] = new_ins.bytes

    local_logger.debug(f"change\n\t{instruction}\n\t{new_ins}\n")


def replace_instruction_reference_offset(self: PatchInfo):
    text_section = self.target.getsectionbyname(".text")
        
    for instruction in disassemble_section(self, ".text"):
        instruction: capstone.CsInsn
        if instruction.id == capstone.x86.X86_INS_NOP:
            continue

        if capstone.CS_GRP_BRANCH_RELATIVE in instruction.groups:
            replace_instruction_reference_offset_relative_branch(self, text_section, instruction)

        for op_index, op in enumerate(instruction.operands):
            if not op.type == capstone.x86.X86_OP_MEM:
                continue

            replace_instruction_reference_operand_mem_offset(self, text_section, instruction, op_index, op)


def replace_relocations(self: PatchInfo):
    text_section = self.target.getsectionbyname(".text")
    rela: ei.RelATable = self.target.getsectionbyname(".rela.dyn")

    for i, rel in enumerate(rela.reltab):
        rel: e.Rela64
        if rel.type != e.R_X86_64_RELATIVE:
            continue
        
        old_symbol: e.Sym64 = get_symbol_at_addr(self, rel.addend)
        if old_symbol is None or old_symbol.name not in self.reference_replacements:
            continue

        new_symbol_name = self.reference_replacements[old_symbol.name]
        new_symbol = self.symbols[new_symbol_name]

        rel.addend = new_symbol.value

        rela[i] = rel

    self.target.build_content()
    self.target.check_coherency()

def get_target_address(pi: PatchInfo, reloc: e.Rela64) -> int:
    symbol_name: str = reloc.symbol.name
    local_logger = getLogger("get_target_address")
    # local_logger.setLevel(logging.DEBUG)

    if symbol_name in pi.virtual_reference:
        local_logger.debug(f"Transformed [{symbol_name}] => [{pi.virtual_reference[symbol_name]}]")
        symbol_name = pi.virtual_reference[symbol_name]

    local_logger.debug(pi.external_full_name)
    local_logger.debug(pi.symbols)

    local_logger.debug(symbol_name)
    if symbol_name in pi.external_full_name:
        local_logger.debug("\tget_plt_address")
        return pi.get_plt_address(symbol_name)
    elif reloc.symbol.type == "SECTION":
        section_name = pi.patch.sections[reloc.shndx].name
        return pi.target.getsectionbyname(section_name).addr + pi.unmodified_target.getsectionbyname(section_name).size
    elif symbol_name in pi.symbols:
        return pi.symbols[symbol_name].value
    else:
        raise Exception(f"Unknown symbol {symbol_name}")

def apply_patch_relocation(self: PatchInfo):
    # TODO: this may not work for all cases
    text_section = self.target.getsectionbyname(".text")
    import_rela: ei.RelATable = self.patch.getsectionbyname(".rela.text")

    if import_rela is None:
        return

    for reloc in import_rela.reltab:
        reloc: e.Rela64
            
        # https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
        # page 71, Table 4.10: Relocation Types
        # print(reloc.readelf_display())
        if reloc.type == e.R_X86_64_PLT32:
            replace_address = self.unmodified_target.getsectionbyname(".text").size + self.target.getsectionbyname(".text").addr + reloc.offset
            symbol_value = get_target_address(self, reloc)
            # print("\t", hex(symbol_value))
            new_value = symbol_value + reloc.addend - replace_address

            text_section.content[
                replace_address - text_section.addr:
                replace_address - text_section.addr + 4
            ] = pack("<i", new_value)

        elif reloc.type == e.R_X86_64_PC32:
            replace_address = self.unmodified_target.getsectionbyname(".text").size + self.target.getsectionbyname(".text").addr + reloc.offset
            symbol_value = get_target_address(self, reloc)
            new_value = symbol_value + reloc.addend - replace_address

            text_section.content[
                replace_address - text_section.addr:
                replace_address - text_section.addr + 4
            ] = pack("<i", new_value)

        elif reloc.type == e.R_X86_64_REX_GOTPCRELX:
            # https://maskray.me/blog/2021-08-29-all-about-global-offset-table#got-indirection-to-pc-relative
            # x86-64's R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX, and R_X86_64_CODE_4_GOTPCRELX optimization
            # can transform
            #   a load/store via GOT to a direct load/store, 
            #   a GOT-indirect call/jump to a direct call/jump.
            # 
            # this is used when it's unknown where the referenced function can be found
            # it can be a runtime imported func => GOT 
            # or a linktime imported => simple relative offset
            # 
            # the transformation consist of replacing the instruction

            replace_address = self.unmodified_target.getsectionbyname(".text").size + self.target.getsectionbyname(".text").addr + reloc.offset
            symbol_name = reloc.name

            if symbol_name in self.external_full_name:
                # symbol_name = self.external_full_name[symbol_name]

                for rela in (self.target.getsectionbyname(".rela.plt") or self.target.getsectionbyname(".rela.dyn")).reltab:
                    if rela.name != symbol_name:
                        continue
                    break
                else:
                    raise Exception(f"not found [{symbol_name}]")

                symbol_value = rela.offset
            else:
                # TODO: proper replace
                # 48 8b 05 00 00 00 00    mov    rax,QWORD PTR [rip+0x0]
                # 48 8d 05 00 00 00 00    lea    rax,[rip+0x0]
                text_section.content[replace_address - text_section.addr - 2] = pack("B", 0x8d)
                
                symbol_value = get_target_address(self, reloc)

            new_value = symbol_value + reloc.addend - replace_address

            text_section.content[
                replace_address - text_section.addr:
                replace_address - text_section.addr + 4
            ] = pack("<i", new_value)
        elif reloc.type == e.R_X86_64_GOTPCRELX:
            # https://maskray.me/blog/2021-08-29-all-about-global-offset-table#got-indirection-to-pc-relative
            # x86-64's R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX, and R_X86_64_CODE_4_GOTPCRELX optimization
            # can transform
            #   a load/store via GOT to a direct load/store, 
            #   a GOT-indirect call/jump to a direct call/jump.
            # 
            # this is used when it's unknown where the referenced function can be found
            # it can be a runtime imported func => GOT 
            # or a linktime imported => simple relative offset
            # 
            # the transformation consist of replacing the instruction

            replace_address = self.unmodified_target.getsectionbyname(".text").size + self.target.getsectionbyname(".text").addr + reloc.offset
            symbol_name = reloc.name

            if symbol_name in self.external_full_name:
                # symbol_name = self.external_full_name[symbol_name]

                for rela in (self.target.getsectionbyname(".rela.plt") or self.target.getsectionbyname(".rela.dyn")).reltab:
                    if rela.name != symbol_name:
                        continue
                    break
                else:
                    raise Exception(f"not found [{symbol_name}]")

                symbol_value = rela.offset
            else:
                # TODO: proper replace
                # ff 15 00 00 00 00       call   *0x0(%rip)
                # e8 03 02 00 00 90       call   137f <change_secret>  ; nop
                text_section.content[replace_address - text_section.addr - 2] = b"\xe8"
                text_section.content[replace_address - text_section.addr + 3] = b"\x90"
                
                replace_address -= 1
                symbol_value = get_target_address(self, reloc)


            # print("symbol_value:", hex(symbol_value))
            new_value = symbol_value + reloc.addend - replace_address

            text_section.content[
                replace_address - text_section.addr:
                replace_address - text_section.addr + 4
            ] = pack("<i", new_value)
        else:
            print(f"Ignoring reloc {reloc.readelf_display()}")
            raise Exception(f"Unknown reloc {reloc.type}")
            continue

        # print(f"\t [{hex(replace_address)}] <- {hex(new_value)}")

    self.target.build_content()
    self.target.check_coherency()


def apply_patch(target_path: Path, patch_path: Path, *, compiled_patch_path:Path = None, output_path: Path = None, symbols_path: Path = None):
    local_logger = getLogger("apply_patch")
    # local_logger.setLevel(logging.DEBUG)
    assert target_path.is_file()
    assert patch_path.is_file()

    if not output_path:
        output_path = target_path.parent / f"{target_path.name}_changed"
    assert not output_path.is_dir()

    check_elf_section_assumsions(target_path)
    pi = PatchInfo(target_path, patch_path, symbols_path=symbols_path, compiled_patch_path=compiled_patch_path)
    pi.extract_patch_instructions()
    expand_sections(pi)
    local_logger.debug(pi.target.sections.readelf_display()),
    local_logger.debug(pi.target.symbols.content[:].hex())

    local_logger.info("[+] DONE repairint code references")

    add_dynamic(pi)
    local_logger.info("[+] DONE Expanding .plt")

    add_program_symbols(pi)
    local_logger.info("[+] DONE appending symbols")

    replace_instruction_reference_offset(pi)
    local_logger.info("[+] DONE replacing function calls")

    replace_relocations(pi)
    local_logger.info("[+] DONE replacing function in from relocation")

    apply_patch_relocation(pi)
    local_logger.info("[+] DONE replacing")

    open(output_path, "wb").write(pi.target.build_content())
    shutil.copymode(target_path, output_path)
    local_logger.info("[+] DONE")
    local_logger.info(f"[+] New executable writen to '{output_path}'")
    local_logger.debug(pi.reference_replacements)


parser = argparse.ArgumentParser(
    prog="ELF Patcher",
    description="Apply patches writen in C to ELF amd64 programs"
)
parser.add_argument(metavar="<target>", type=Path, dest="target_path")
parser.add_argument(metavar="<patch>", type=Path, dest="patch_path")
parser.add_argument("-c", metavar="<output>", type=Path, dest="compiled_patch_path")
parser.add_argument("-o", metavar="<output>", type=Path, dest="output_path")
parser.add_argument("-s", "--symbols", metavar="<symbols_file>", required=False, type=Path, dest="symbols_path")


def main():
    apply_patch(**vars(parser.parse_args()))

if __name__ == "__main__":
    main()
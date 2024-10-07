import elfesteem.elf as elf
import elfesteem.elf_init as elf_init

from elfesteem.elf_init import SymTable, RelATable
from address_translator import *

__all__ = [
    elf,
    elf_init
]

def SymTable_translate(self, translator: Address_Translator):
    for i, rel in enumerate(self.symtab):
        rel: elf.Sym64
        # print(repr(rel), hex(rel.info), hex(rel.value))

        # rel.offset = translator.translate_offset(rel.offset)
        rel.value = translator.translate_address(rel.value)

        self[i] = rel
SymTable.translate = SymTable_translate


def RelATable_translate(self, translator: Address_Translator):
    for i, rela in enumerate(self.reltab):
        rela: elf.Rela64
        rela.offset = translator.translate_address(rela.offset)
        rela.addend = translator.translate_address(rela.addend)

        self[i] = rela
RelATable.translate = RelATable_translate
from collections import namedtuple
from dataclasses import dataclass, field
from functools import partial, lru_cache
from operator import attrgetter
from typing import List
from math import copysign

__all__ = [
    "Inserted_Memory",
    "Address_Translator",
    "Inserted_Memory_Regions"
]

@dataclass
class Inserted_Memory:
    base_addr: int
    size: int

    def __repr__(self):
        return f"Insertion[{self.base_addr:5x} { ' ' if self.size >= 0 else '-'}{abs(self.size):3x}]"

@dataclass
class Inserted_Memory_Regions:
    in_addres_space: List[Inserted_Memory] = field(default_factory=list)
    in_file_space: List[Inserted_Memory] = field(default_factory=list)

    def __iadd__(self, other: "Inserted_Memory_Regions"):
        self.in_addres_space += other.in_addres_space
        self.in_file_space += other.in_file_space
        return self

@dataclass
class Address_Translator:
    file_insertions: List[Inserted_Memory] = field(default_factory=list)
    address_insertions: List[Inserted_Memory] = field(default_factory=list)

    @staticmethod
    def translate(address:int, insertions: List[Inserted_Memory]) -> int:
        assert not __class__.is_consumed(address, insertions)

        return address + sum(map(
            lambda inserted_memory:(
                inserted_memory.size if inserted_memory.base_addr <= address
                else 0
            ),
            insertions
        ))

    def translate_address(self, address: int) -> int:
        return self.translate(address, self.address_insertions)
    def translate_offset(self, address: int) -> int:
        return self.translate(address, self.file_insertions)

    # n: diff between address and the result
    # i: elements in insertions

    @staticmethod
    def reverse_translation(address:int, insertions: List[Inserted_Memory]) -> int:
        # O(i) defective

        # list already sorted in insert
        for inserted_memory in insertions[::1]:
            # if inserted_memory.base_addr < address and inserted_memory.base_addr + inserted_memory.size < address and \
            # if (inserted_memory.base_addr < address if inserted_memory.size > 0 else inserted_memory.base_addr + inserted_memory.size < address ) and inserted_memory.base_addr + inserted_memory.size <= address and \
            if (inserted_memory.base_addr + abs(inserted_memory.size) <= address if inserted_memory.size > 0 else inserted_memory.base_addr < address ) and \
                    address - inserted_memory.size > 0:
                address -= inserted_memory.size
                # print("\t", inserted_memory, "=>", hex(address))
            else:
                pass
                # print("\t", inserted_memory, "=>", hex(address))
                # print("\t\t", inserted_memory.base_addr < address, inserted_memory.base_addr < address)
                # print("\t\t", inserted_memory.base_addr + inserted_memory.size <= address)

        return address
    
    @staticmethod
    def reverse_translation2(address:int, insertions: List[Inserted_Memory]) -> int:
        # O(i) defective

        # print("start:", hex(address))
        cummulative = 0
        # list already sorted in insert
        for inserted_memory in insertions[::1]:
            # if inserted_memory.base_addr < address and inserted_memory.base_addr + inserted_memory.size < address and \
            # if (inserted_memory.base_addr < address if inserted_memory.size > 0 else inserted_memory.base_addr + inserted_memory.size < address ) and inserted_memory.base_addr + inserted_memory.size <= address and \
            if (inserted_memory.base_addr + abs(inserted_memory.size) <= address if inserted_memory.size > 0 else inserted_memory.base_addr <= address ) and \
                    address - inserted_memory.size > 0:
                # address -= inserted_memory.size
                cummulative -= inserted_memory.size
                # print("\t", inserted_memory, "=>", hex(address))
            else:
                pass
                # print("\t", inserted_memory, "=>", hex(address))
                # print("\t\t", inserted_memory.base_addr < address, inserted_memory.base_addr < address)
                # print("\t\t", inserted_memory.base_addr + inserted_memory.size <= address)

        return address + cummulative

    @staticmethod
    def reverse_translation3(address:int, insertions: List[Inserted_Memory]) -> int:
        # O(i * log(n)) defective

        @lru_cache
        def translate(address: int) -> int: return Address_Translator.translate(address, insertions)
        @lru_cache
        def is_consumed(address: int) -> int: return Address_Translator.is_consumed(address, insertions)
        # make it work then is_consumed() == False
        g0 = translate(address)

        step = 0x10 * (1 if address >= g0 else -1)

        # binary search bounds search
        a, b = address, address + step

        while not (translate(a) <= address <= translate(b) or translate(b) <= address <= translate(a)):
            # print(f"{a:x}\t\t\t{b:x}")
            # print(f"{translate(a):x} <= {address:x} <= {translate(b):x}")
            a = b
            b += step
            step *= 2

            if abs(step) > 0xffff:
                exit()

        print(f"{a:x}\t\t\t{b:x}")
        print(f"{translate(a):x} <= {address:x} <= {translate(b):x}")

        a, b = sorted([a, b])

        while a < b:
            center = (a + b) // 2
            print()
            print(f"\t{translate(center)}")
            print(f"{a:x}\t{center:x}\t{b:x}")

            if translate(center) == address:
                return center

            if translate(center) > address:
                b = center - 1
            else:
                a = center + 1

        assert translate(a) == address
        return a


    @staticmethod
    def reverse_translation4(address:int, insertions: List[Inserted_Memory]) -> int:
        # O(i*n)
        
        def translate(address: int) -> int: return Address_Translator.translate(address, insertions)
        def is_consumed(address: int) -> int: return Address_Translator.is_consumed(address, insertions)

        g0_check = address
        while is_consumed(g0_check):
            g0_check += 1
        g0 = translate(g0_check)

        step = 0x1 * (1 if address >= g0 else -1)
        check = g0_check

        while True:
            if not is_consumed(check) and translate(check) == address:
                return check

            check += step
    
    @staticmethod
    def reverse_translation5(address:int, insertions: List[Inserted_Memory]) -> int:
        # TODO: precalculate this for better permormance
        # tranlations is done with `tranlate(add - 1) + 1` bc the base need only be affected by previous inserions
        return Address_Translator.translate(address, [Inserted_Memory(Address_Translator.translate(ins.base_addr-1, insertions)+1, -ins.size) for ins in insertions])

    def reverse_translation_address(self, address: int) -> int:
        return self.reverse_translation5(address, self.address_insertions)
    def reverse_translation_offset(self, address: int) -> int:
        return self.reverse_translation5(address, self.file_insertions)

    def consolidate(self, els: List[Inserted_Memory]):
        new_els = []
        skipable = 0

        for i, el in enumerate(els):
            if skipable > 0:
                skipable -= 1
                continue

            while i + 1 + skipable < len(els) and el.base_addr == els[i + 1 + skipable].base_addr:
                el.size += els[i + 1 + skipable].size
                skipable += 1

            new_els.append(el)

        
        if len(els) != len(new_els):
            return self.consolidate(new_els)

        return els

    def add_for_address(self, el: Inserted_Memory):
        self.address_insertions.append(el)
        self.address_insertions.sort(key=attrgetter('base_addr', 'size'))
        self.address_insertions = self.consolidate(self.address_insertions)
    def add_for_offset(self, el: Inserted_Memory):
        self.file_insertions.append(el)
        self.file_insertions.sort(key=attrgetter('base_addr', 'size'))
        self.file_insertions = self.consolidate(self.file_insertions)

    def add_all_for_address(self, els):
        for el in els:
            self.add_for_address(el)
    def add_all_for_offset(self, els):
        for el in els:
            self.add_for_offset(el)

    @staticmethod
    def is_consumed(address: int, insertions: List[Inserted_Memory]) -> int:
        is_last_negative = False
        for inserted_memory in insertions:
            is_last_negative = (address + inserted_memory.size < inserted_memory.base_addr) if inserted_memory.base_addr <= address else is_last_negative
        
        return is_last_negative

    def is_consumed_address(self, address: int) -> int:
        return self.is_consumed(address, self.address_insertions)
    def is_consumed_offset(self, address: int) -> int:
        return self.is_consumed(address, self.file_insertions)


def test_basic():
    test_basic1()
    test_basic2()
    test_basic3()
    test_basic4()

    test_basic_reverse1()
    test_basic_reverse2()
    pass
    test_basic_reverse4()

    test_unique()

    test_regresion1()
    test_regresion1_full()

def test_basic1():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  0x0010))

    assert tra.translate_address(0x10) == 0x10
    assert tra.translate_address(0xff) == 0xff

    assert tra.translate_address(0x100) == 0x110
    assert tra.translate_address(0x101) == 0x111
    assert tra.translate_address(0x10f) == 0x11f

    assert tra.translate_address(0x1ff) == 0x20f
    assert tra.translate_address(0x200) == 0x210
    
def test_basic_reverse1():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  0x0010))
    
    assert tra.reverse_translation_address(0x10) == 0x10
    assert tra.reverse_translation_address(0xff) == 0xff

    assert tra.reverse_translation_address(0x110) == 0x100
    assert tra.reverse_translation_address(0x111) == 0x101
    assert tra.reverse_translation_address(0x11f) == 0x10f

    assert tra.reverse_translation_address(0x20f) == 0x1ff
    assert tra.reverse_translation_address(0x210) == 0x200

def test_basic2():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  -0x0010))

    assert tra.translate_address(0x10) == 0x10
    assert tra.translate_address(0xff) == 0xff

    assert tra.is_consumed_address(0x100)
    assert tra.is_consumed_address(0x101)
    assert tra.is_consumed_address(0x10f)

    
    assert tra.translate_address(0x110) == 0x100
    assert tra.translate_address(0x111) == 0x101
    assert tra.translate_address(0x11f) == 0x10f

    assert tra.translate_address(0x1ff) == 0x1ef
    assert tra.translate_address(0x200) == 0x1f0

def test_basic_reverse2():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  -0x0010))

    assert tra.reverse_translation_address(0x10) == 0x10
    assert tra.reverse_translation_address(0xff) == 0xff

    assert tra.reverse_translation_address(0x100) == 0x110
    assert tra.reverse_translation_address(0x101) == 0x111
    assert tra.reverse_translation_address(0x10f) == 0x11f

    assert tra.reverse_translation_address(0x1ef) == 0x1ff
    assert tra.reverse_translation_address(0x1f0) == 0x200

def test_basic3():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  0x0010))
    tra.add_for_address(Inserted_Memory(0x120,  -0x0010))

    assert tra.translate_address(0x10) == 0x10
    assert tra.translate_address(0xff) == 0xff

    assert tra.translate_address(0x100) == 0x110
    assert tra.translate_address(0x101) == 0x111
    assert tra.translate_address(0x10f) == 0x11f

    assert tra.translate_address(0x110) == 0x120
    assert tra.translate_address(0x111) == 0x121
    assert tra.translate_address(0x11f) == 0x12f

    assert tra.is_consumed_address(0x120)
    assert tra.is_consumed_address(0x121)
    assert tra.is_consumed_address(0x12f)

    assert tra.translate_address(0x130) == 0x130
    assert tra.translate_address(0x131) == 0x131
    assert tra.translate_address(0x13f) == 0x13f

    assert tra.translate_address(0x1ff) == 0x1ff
    assert tra.translate_address(0x200) == 0x200

def test_basic4():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  0x0100))
    tra.add_for_address(Inserted_Memory(0x110,  -0x0010))

    assert tra.translate_address(0x10) == 0x10
    assert tra.translate_address(0xff) == 0xff

    assert tra.translate_address(0x100) == 0x200
    assert tra.translate_address(0x101) == 0x201
    assert tra.translate_address(0x10f) == 0x20f

    assert tra.is_consumed_address(0x110)
    assert tra.is_consumed_address(0x111)
    assert tra.is_consumed_address(0x11f)
    
    assert tra.translate_address(0x120) == 0x210
    assert tra.translate_address(0x121) == 0x211
    assert tra.translate_address(0x12f) == 0x21f

    assert tra.translate_address(0x2ff) == 0x3ef
    assert tra.translate_address(0x300) == 0x3f0

def test_basic_reverse4():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  0x0100))
    tra.add_for_address(Inserted_Memory(0x110,  -0x0010))

    assert tra.reverse_translation_address(0x10) == 0x10
    assert tra.reverse_translation_address(0xff) == 0xff

    assert tra.reverse_translation_address(0x200) == 0x100
    assert tra.reverse_translation_address(0x201) == 0x101
    assert tra.reverse_translation_address(0x20f) == 0x10f

    assert tra.reverse_translation_address(0x210) == 0x120
    assert tra.reverse_translation_address(0x211) == 0x121
    assert tra.reverse_translation_address(0x21f) == 0x12f

    assert tra.reverse_translation_address(0x3ef) == 0x2ff
    assert tra.reverse_translation_address(0x3f0) == 0x300

def test_regresion1():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x100,  0x020))
    tra.add_for_address(Inserted_Memory(0x110, -0x020))

    assert tra.translate_address(0x10) == 0x10
    assert tra.translate_address(0xff) == 0xff
    assert tra.reverse_translation_address(0x10) == 0x10
    assert tra.reverse_translation_address(0xff) == 0xff

    assert tra.translate_address(0x100) == 0x120
    assert tra.translate_address(0x101) == 0x121
    assert tra.translate_address(0x10f) == 0x12f

    assert tra.reverse_translation_address(0x120) == 0x100
    assert tra.reverse_translation_address(0x121) == 0x101
    assert tra.reverse_translation_address(0x12f) == 0x10f

    assert tra.is_consumed_address(0x110)
    assert tra.is_consumed_address(0x111)
    assert tra.is_consumed_address(0x11f)

    assert tra.reverse_translation_address(0x210) == 0x210
    assert tra.reverse_translation_address(0x211) == 0x211
    assert tra.reverse_translation_address(0x21f) == 0x21f

    assert tra.reverse_translation_address(0x2ff) == 0x2ff
    assert tra.reverse_translation_address(0x300) == 0x300

def test_regresion1():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x1207,  0x044))
    tra.add_for_address(Inserted_Memory(0x1216, -0x044))

    assert tra.translate_address(0x1206) == 0x1206
    assert tra.reverse_translation_address(0x1206) == 0x1206

    assert tra.translate_address(0x1207) == 0x1207 + 0x44
    assert tra.reverse_translation_address(0x1207 + 0x44) == 0x1207

    assert tra.translate_address(0x1208) == 0x1208 + 0x44
    assert tra.reverse_translation_address(0x1208 + 0x44) == 0x1208

    assert tra.is_consumed_address(0x1216)
    assert tra.is_consumed_address(0x1217)
    assert tra.is_consumed_address(0x1216 + 0x43)

def test_regresion1_full():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x1207,  0x044))
    tra.add_for_address(Inserted_Memory(0x1216, -0x044))

    tra.add_for_address(Inserted_Memory(0x401f,  0x000))
    tra.add_for_address(Inserted_Memory(0x4020,  0x004))
    tra.add_for_address(Inserted_Memory(0x4028,  0x00c))

    assert tra.is_consumed_address(0x1216)
    assert tra.is_consumed_address(0x1217)
    assert tra.is_consumed_address(0x124c)
    assert tra.is_consumed_address(0x1259)

    assert not tra.is_consumed_address(0x125a)

    assert tra.translate_address(0x1206) == 0x1206
    assert tra.reverse_translation_address(0x1206) == 0x1206

    assert tra.translate_address(0x1207) == 0x1207 + 0x44
    assert tra.reverse_translation_address(0x1207 + 0x44) == 0x1207

    assert tra.translate_address(0x1208) == 0x1208 + 0x44
    assert tra.reverse_translation_address(0x1208 + 0x44) == 0x1208

    assert tra.is_consumed_address(0x1216)
    assert tra.is_consumed_address(0x1217)
    assert tra.is_consumed_address(0x1216 + 0x43)


def test_unique():
    tra = Address_Translator()
    tra.add_for_address(Inserted_Memory(0x1173,  0x0010))
    tra.add_for_address(Inserted_Memory(0x1184, -0x0010))
    
    res = {}
    for i in range(0x5000):
        if tra.is_consumed_address(i):
            continue

        tra_i = tra.translate_address(i)
        if tra_i in res:
            raise Exception(f"[{i:x}, {res[tra_i]:x}] => {tra_i:x}")
        res[tra_i] = i

def test_independese1():
    tra=Address_Translator()
    tra.add_for_address(Inserted_Memory(0,  0x1000))
    tra.add_for_address(Inserted_Memory(0x1000,  0x1000))
    tra.add_for_address(Inserted_Memory(0x2000,  0x1000))
    for i in range(0x5000):
        assert i == tra.translate_offset(i)

def test_independese2():
    tra=Address_Translator()
    tra.add_for_offset(Inserted_Memory(0,  0x1000))
    tra.add_for_offset(Inserted_Memory(0x1000,  0x1000))
    tra.add_for_offset(Inserted_Memory(0x2000,  0x1000))
    for i in range(0x5000):
        assert i == tra.translate_address(i)

def test_independese3():
    tra=Address_Translator()
    tra.add_for_address(Inserted_Memory(0,  0x1000))
    tra.add_for_offset(Inserted_Memory(0,  0x2000))

    for i in range(1, 0x5000):
        # print(i, tra.translate_address(i), tra.translate_offset(i))
        assert tra.translate_address(i) == i + 0x1000
        assert tra.translate_offset(i) == i + 0x2000

def test_independese():
    test_independese1()
    test_independese2()
    test_independese3()

def test_basic_functionality():
    tra=Address_Translator()

    tra.add_for_address(Inserted_Memory(0x1173,  0x0010))
    tra.add_for_address(Inserted_Memory(0x1184, -0x0010))

    print(tra.is_consumed_address(0))
    print(tra.is_consumed_address(4481))

    print(tra.address_insertions)

    for i in range(0x8000):
        if tra.is_consumed_address(i):
            continue

        # print(f"{hex(i)} => {hex(tra.translate_address(i))} => {hex(tra.reverse_translation_address(tra.translate_address(i)))}")
        if i != tra.reverse_translation_address(tra.translate_address(i)):
            print()
            print(f"{hex(i)} => {hex(tra.translate_address(i))} => {hex(tra.reverse_translation_address(tra.translate_address(i)))}", flush=True)
            exit(1)

if __name__ == "__main__":
    test_basic()
    test_basic_functionality()
    test_independese()
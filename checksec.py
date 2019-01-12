'''
ELF hardening checker class, copy inspired / taken from https://github.com/kholia/checksec
'''


from re import search

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


STACK_CHK = set(["__stack_chk_fail", "__stack_smash_handler"])


class Elf:
    def __init__(self, fileobj):
        self.fileobj = fileobj
        self._elffile = None

    @property
    def elffile(self):
        if not self._elffile:
            self._elffile = ELFFile(self.fileobj)
        return self._elffile

    def _file_has_magic(self, fileobj, magic_bytes):
        length = len(magic_bytes)
        magic = fileobj.read(length)
        fileobj.seek(0)
        return magic == magic_bytes

    def is_elf(self):
        "Take file object, peek at the magic bytes to check if ELF file."
        return self._file_has_magic(self.fileobj, b"\x7fELF")

    def dynamic_tags(self, key="DT_RPATH"):
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == key:
                    return True
            return False

    def is_relro(self):
        if self.elffile.num_segments() == 0:
            return False

        have_relro = False
        for segment in self.elffile.iter_segments():
            if search("GNU_RELRO", str(segment['p_type'])):
                have_relro = True
                break

        if self.dynamic_tags("DT_BIND_NOW") and have_relro:
            return True
        else:
            # Partial
            return False
        return False

    def canary(self):
        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                continue
            for _, symbol in enumerate(section.iter_symbols()):
                if symbol.name in STACK_CHK:
                    return True
        return False

    def pie(self):
        header = self.elffile.header
        if self.dynamic_tags("EXEC"):
            return False
        if "ET_DYN" in header['e_type']:
            if self.dynamic_tags("DT_DEBUG"):
                return True
            else:
                # DSO is PIE
                return True
        return False

// read_uleb128, read_sleb128, sold_Unwind_Ptr, read_encoded_value_with_base
// were copied from sysdeps/generic/unwind-pe.h in glibc. Free Software
// Foundation, Inc. holds the copyright for them.  The sold authors hold the
// copyright for the other part of this source code.
//
// Copyright (C) 2021 The sold authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// Copyright (C) 2012-2021 Free Software Foundation, Inc.
// Written by Ian Lance Taylor, Google.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) The name of the author may not be used to
//     endorse or promote products derived from this software without
//     specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "utils.h"

#include <iomanip>

std::vector<std::string> SplitString(const std::string& str,
                                     const std::string& sep) {
    std::vector<std::string> ret;
    if (str.empty()) return ret;
    size_t index = 0;
    while (true) {
        size_t next = str.find(sep, index);
        ret.push_back(str.substr(index, next - index));
        if (next == std::string::npos) break;
        index = next + 1;
    }
    return ret;
}

std::string EscapedString(const std::vector<char>& chrs) {
    std::string ret;
    for (const auto c : chrs) {
        if ((' ' <= c && c <= '[') || (']' <= c && c <= '~')) {
            ret += c;
        } else {
            switch (c) {
                case '\'':
                    ret += "\\'";
                    break;
                case '\"':
                    ret += "\\\"";
                    break;
                case '\?':
                    ret += "\\?";
                    break;
                case '\\':
                    ret += "\\";
                    break;
                case '\0':
                    ret += "\\0";
                    break;
                default:
                    LOG(FATAL) << SOLD_LOG_BITS(c);
            }
        }
    }
    return ret;
}

std::vector<char> GetChars(const std::string& str) {
    std::vector<char> ret;
    for (int i = 0; i < str.size(); i++) {
        if (str[i] != '\\') {
            ret.emplace_back(str[i]);
        } else {
            CHECK(i + 1 < str.size());
            switch (str[i + 1]) {
                case '\'':
                    ret.emplace_back('\'');
                    break;
                case '"':
                    ret.emplace_back('\"');
                    break;
                case '?':
                    ret.emplace_back('\?');
                    break;
                case '\\':
                    ret.emplace_back('\\');
                    break;
                case '0':
                    ret.emplace_back('\0');
                    break;
                default:
                    LOG(FATAL) << SOLD_LOG_BITS(str[i + 1]);
            }
            i++;
        }
    }
    return ret;
}

bool HasPrefix(const std::string& str, const std::string& prefix) {
    ssize_t size_diff = str.size() - prefix.size();
    return size_diff >= 0 && str.substr(0, prefix.size()) == prefix;
}

uintptr_t AlignNext(uintptr_t a, uintptr_t mask) { return (a + mask) & ~mask; }

void WriteBuf(FILE* fp, const void* buf, size_t size) {
    CHECK(fwrite(buf, 1, size, fp) == size);
}

void EmitZeros(FILE* fp, uintptr_t cnt) {
    std::string zero(cnt, '\0');
    WriteBuf(fp, zero.data(), zero.size());
}

void EmitPad(FILE* fp, uintptr_t to) {
    uint pos = ftell(fp);
    CHECK_GE(pos, 0);
    CHECK_LE(pos, to);
    EmitZeros(fp, to - pos);
}

void MemcpyFile(FILE* fp, uintptr_t offset, const void* src, size_t size) {
    uint pos = ftell(fp);
    CHECK_GE(offset, 0);
    CHECK_GE(size, 0);
    CHECK_LT(offset + size, pos);
    fseek(fp, offset, SEEK_SET);
    fwrite(src, 1, size, fp);
    fseek(fp, pos, SEEK_SET);
}

void EmitAlign(FILE* fp) {
    long pos = ftell(fp);
    CHECK(pos >= 0);
    EmitZeros(fp, AlignNext(pos) - pos);
}

bool IsTLS(const Elf_Sym& sym) { return ELF_ST_TYPE(sym.st_info) == STT_TLS; }

bool IsDefined(const Elf_Sym& sym) {
    return (sym.st_value || IsTLS(sym)) && sym.st_shndx != SHN_UNDEF;
}

std::ostream& operator<<(std::ostream& os, const Syminfo& s) {
    auto f = os.flags();
    os << "Syminfo{name=" << s.name << ", soname=" << s.soname
       << ", version=" << s.version << ", versym=" << s.versym << ", sym=0x"
       << std::hex << std::setfill('0') << std::setw(16) << s.sym << "}";
    os.flags(f);
    return os;
}

std::string ShowDW_EH_PE(uint8_t type) {
    if (type == DW_EH_PE_omit) {
        return "DW_EH_PE_omit";
    }

    std::string ret;

    switch (type & 0xf) {
        case DW_EH_PE_absptr:
            ret = "DW_EH_PE_absptr";
            break;
        case DW_EH_PE_uleb128:
            ret = "DW_EH_PE_uleb128";
            break;
        case DW_EH_PE_udata2:
            ret = "DW_EH_PE_udata2";
            break;
        case DW_EH_PE_udata4:
            ret = "DW_EH_PE_udata4";
            break;
        case DW_EH_PE_udata8:
            ret = "DW_EH_PE_udata8";
            break;
        case DW_EH_PE_sleb128:
            ret = "DW_EH_PE_sleb128";
            break;
        case DW_EH_PE_sdata2:
            ret = "DW_EH_PE_sdata2";
            break;
        case DW_EH_PE_sdata4:
            ret = "DW_EH_PE_sdata4";
            break;
        case DW_EH_PE_sdata8:
            ret = "DW_EH_PE_sdata8";
            break;
    }

    switch (type & 0xf0) {
        case DW_EH_PE_pcrel:
            ret += " + DW_EH_PE_pcrel";
            break;
        case DW_EH_PE_textrel:
            ret += " + DW_EH_PE_textrel";
            break;
        case DW_EH_PE_datarel:
            ret += " + DW_EH_PE_datarel";
            break;
        case DW_EH_PE_funcrel:
            ret += " + DW_EH_PE_funcrel";
            break;
        case DW_EH_PE_aligned:
            ret += " + DW_EH_PE_aligned";
            break;
    }

    if (type == DW_EH_PE_SOLD_DUMMY) {
        ret = "DW_EH_PE_SOLD_DUMMY(0xEE)";
    } else if (ret == "") {
        ret = HexString(type, 2);
    }

    return ret;
}

std::string ShowDynamicEntryType(int type) {
    switch (type) {
        case DT_NULL:
            return "DT_NULL";
        case DT_NEEDED:
            return "DT_NEEDED";
        case DT_PLTRELSZ:
            return "DT_PLTRELSZ";
        case DT_PLTGOT:
            return "DT_PLTGOT";
        case DT_HASH:
            return "DT_HASH";
        case DT_STRTAB:
            return "DT_STRTAB";
        case DT_SYMTAB:
            return "DT_SYMTAB";
        case DT_RELA:
            return "DT_RELA";
        case DT_RELASZ:
            return "DT_RELASZ";
        case DT_RELAENT:
            return "DT_RELAENT";
        case DT_STRSZ:
            return "DT_STRSZ";
        case DT_SYMENT:
            return "DT_SYMENT";
        case DT_INIT:
            return "DT_INIT";
        case DT_FINI:
            return "DT_FINI";
        case DT_SONAME:
            return "DT_SONAME";
        case DT_RPATH:
            return "DT_RPATH";
        case DT_SYMBOLIC:
            return "DT_SYMBOLIC";
        case DT_REL:
            return "DT_REL";
        case DT_RELSZ:
            return "DT_RELSZ";
        case DT_RELENT:
            return "DT_RELENT";
        case DT_PLTREL:
            return "DT_PLTREL";
        case DT_DEBUG:
            return "DT_DEBUG";
        case DT_TEXTREL:
            return "DT_TEXTREL";
        case DT_JMPREL:
            return "DT_JMPREL";
        case DT_BIND_NOW:
            return "DT_BIND_NOW";
        case DT_INIT_ARRAY:
            return "DT_INIT_ARRAY";
        case DT_FINI_ARRAY:
            return "DT_FINI_ARRAY";
        case DT_INIT_ARRAYSZ:
            return "DT_INIT_ARRAYSZ";
        case DT_FINI_ARRAYSZ:
            return "DT_FINI_ARRAYSZ";
        case DT_RUNPATH:
            return "DT_RUNPATH";
        case DT_FLAGS:
            return "DT_FLAGS";
        case DT_ENCODING:
            return "DT_ENCODING";
        case DT_PREINIT_ARRAYSZ:
            return "DT_PREINIT_ARRAYSZ";
        case DT_SYMTAB_SHNDX:
            return "DT_SYMTAB_SHNDX";
        case DT_NUM:
            return "DT_NUM";
        case DT_LOOS:
            return "DT_LOOS";
        case DT_HIOS:
            return "DT_HIOS";
        case DT_LOPROC:
            return "DT_LOPROC";
        case DT_HIPROC:
            return "DT_HIPROC";
        case DT_PROCNUM:
            return "DT_PROCNUM";
        case DT_VALRNGLO:
            return "DT_VALRNGLO";
        case DT_GNU_PRELINKED:
            return "DT_GNU_PRELINKED";
        case DT_GNU_CONFLICTSZ:
            return "DT_GNU_CONFLICTSZ";
        case DT_GNU_LIBLISTSZ:
            return "DT_GNU_LIBLISTSZ";
        case DT_CHECKSUM:
            return "DT_CHECKSUM";
        case DT_PLTPADSZ:
            return "DT_PLTPADSZ";
        case DT_MOVEENT:
            return "DT_MOVEENT";
        case DT_MOVESZ:
            return "DT_MOVESZ";
        case DT_FEATURE_1:
            return "DT_FEATURE_1";
        case DT_POSFLAG_1:
            return "DT_POSFLAG_1";
        case DT_SYMINSZ:
            return "DT_SYMINSZ";
        case DT_SYMINENT:
            return "DT_SYMINENT";
        case DT_ADDRRNGLO:
            return "DT_ADDRRNGLO";
        case DT_GNU_HASH:
            return "DT_GNU_HASH";
        case DT_TLSDESC_PLT:
            return "DT_TLSDESC_PLT";
        case DT_TLSDESC_GOT:
            return "DT_TLSDESC_GOT";
        case DT_GNU_CONFLICT:
            return "DT_GNU_CONFLICT";
        case DT_GNU_LIBLIST:
            return "DT_GNU_LIBLIST";
        case DT_CONFIG:
            return "DT_CONFIG";
        case DT_DEPAUDIT:
            return "DT_DEPAUDIT";
        case DT_AUDIT:
            return "DT_AUDIT";
        case DT_PLTPAD:
            return "DT_PLTPAD";
        case DT_MOVETAB:
            return "DT_MOVETAB";
        case DT_SYMINFO:
            return "DT_SYMINFO";
        case DT_VERSYM:
            return "DT_VERSYM";
        case DT_RELACOUNT:
            return "DT_RELACOUNT";
        case DT_RELCOUNT:
            return "DT_RELCOUNT";
        case DT_FLAGS_1:
            return "DT_FLAGS_";
        case DT_VERDEF:
            return "DT_VERDE";
        case DT_VERDEFNUM:
            return "DT_VERDEFNU";
        case DT_VERNEED:
            return "DT_VERNEE";
        case DT_VERNEEDNUM:
            return "DT_VERNEEDNUM";
        case DT_AUXILIARY:
            return "DT_AUXILIARY";
        default:
            LOG(FATAL) << "Unknown type" << SOLD_LOG_BITS(type);
    }
}

std::string ShowRelocationType(int type) {
    switch (type) {
        case R_X86_64_NONE:
            return "R_X86_64_NONE";
        case R_X86_64_64:
            return "R_X86_64_64";
        case R_X86_64_PC32:
            return "R_X86_64_PC32";
        case R_X86_64_GOT32:
            return "R_X86_64_GOT32";
        case R_X86_64_PLT32:
            return "R_X86_64_PLT32";
        case R_X86_64_COPY:
            return "R_X86_64_COPY";
        case R_X86_64_GLOB_DAT:
            return "R_X86_64_GLOB_DAT";
        case R_X86_64_JUMP_SLOT:
            return "R_X86_64_JUMP_SLOT";
        case R_X86_64_RELATIVE:
            return "R_X86_64_RELATIVE";
        case R_X86_64_GOTPCREL:
            return "R_X86_64_GOTPCREL";
        case R_X86_64_32:
            return "R_X86_64_32";
        case R_X86_64_32S:
            return "R_X86_64_32S";
        case R_X86_64_16:
            return "R_X86_64_16";
        case R_X86_64_PC16:
            return "R_X86_64_PC16";
        case R_X86_64_8:
            return "R_X86_64_8";
        case R_X86_64_PC8:
            return "R_X86_64_PC8";
        case R_X86_64_DTPMOD64:
            return "R_X86_64_DTPMOD64";
        case R_X86_64_DTPOFF64:
            return "R_X86_64_DTPOFF64";
        case R_X86_64_TPOFF64:
            return "R_X86_64_TPOFF64";
        case R_X86_64_TLSGD:
            return "R_X86_64_TLSGD";
        case R_X86_64_TLSLD:
            return "R_X86_64_TLSLD";
        case R_X86_64_DTPOFF32:
            return "R_X86_64_DTPOFF32";
        case R_X86_64_GOTTPOFF:
            return "R_X86_64_GOTTPOFF";
        case R_X86_64_TPOFF32:
            return "R_X86_64_TPOFF32";
        case R_X86_64_PC64:
            return "R_X86_64_PC64";
        case R_X86_64_GOTOFF64:
            return "R_X86_64_GOTOFF64";
        case R_X86_64_GOTPC32:
            return "R_X86_64_GOTPC32";
        case R_X86_64_GOT64:
            return "R_X86_64_GOT64";
        case R_X86_64_GOTPCREL64:
            return "R_X86_64_GOTPCREL64";
        case R_X86_64_GOTPC64:
            return "R_X86_64_GOTPC64";
        case R_X86_64_GOTPLT64:
            return "R_X86_64_GOTPLT64";
        case R_X86_64_PLTOFF64:
            return "R_X86_64_PLTOFF64";
        case R_X86_64_SIZE32:
            return "R_X86_64_SIZE32";
        case R_X86_64_SIZE64:
            return "R_X86_64_SIZE64";
        case R_X86_64_GOTPC32_TLSDESC:
            return "R_X86_64_GOTPC32_TLSDESC";
        case R_X86_64_TLSDESC:
            return "R_X86_64_TLSDESC";
        case R_X86_64_IRELATIVE:
            return "R_X86_64_IRELATIVE";
        case R_X86_64_RELATIVE64:
            return "R_X86_64_RELATIVE64";
        case R_X86_64_GOTPCRELX:
            return "R_X86_64_GOTPCRELX";
        case R_X86_64_REX_GOTPCRELX:
            return "R_X86_64_REX_GOTPCRELX";
        case R_X86_64_NUM:
            return "R_X86_64_NUM";
        default: {
            return HexString(type, 4);
        }
    }
}

const std::map<Elf_Word, std::string> SHFToStr = {
    {SHF_WRITE, "SHF_WRITE"},
    {SHF_ALLOC, "SHF_ALLOC"},
    {SHF_EXECINSTR, "SHF_EXECINSTR"},
    {SHF_MERGE, "SHF_MERGE"},
    {SHF_STRINGS, "SHF_STRINGS"},
    {SHF_INFO_LINK, "SHF_INFO_LINK"},
    {SHF_LINK_ORDER, "SHF_LINK_ORDER"},
    {SHF_OS_NONCONFORMING, "SHF_OS_NONCONFORMING"},
    {SHF_GROUP, "SHF_GROUP"},
    {SHF_TLS, "SHF_TLS"},
    {SHF_COMPRESSED, "SHF_COMPRESSED"},
    {SHF_MASKOS, "SHF_MASKOS"},
    {SHF_MASKPROC, "SHF_MASKPROC"},
    {SHF_ORDERED, "SHF_ORDERED"},
    {SHF_EXCLUDE, "SHF_EXCLUDE"}};

std::vector<std::string> ShowShdrFlags(Elf_Word sh_flags) {
    std::vector<std::string> ret;
    for (const auto& [f, s] : SHFToStr) {
        if (f & sh_flags) {
            ret.emplace_back(s);
            sh_flags ^= f;
        }
    }
    if (sh_flags) {
        ret.emplace_back(HexString(sh_flags));
    }
    return ret;
}

Elf_Word ReadShdrFlags(std::vector<std::string> strs) {
    Elf_Word flags = 0;
    static const auto StrToSHF = InvertMap(SHFToStr);
    for (const auto& s : strs) {
        CHECK(StrToSHF.contains(s));
        flags |= StrToSHF.at(s);
    }
    return flags;
}

const std::map<Elf_Word, std::string> SHTToStr = {
    {SHT_NULL, "SHT_NULL"},
    {SHT_PROGBITS, "SHT_PROGBITS"},
    {SHT_SYMTAB, "SHT_SYMTAB"},
    {SHT_STRTAB, "SHT_STRTAB"},
    {SHT_RELA, "SHT_RELA"},
    {SHT_HASH, "SHT_HASH"},
    {SHT_DYNAMIC, "SHT_DYNAMIC"},
    {SHT_NOTE, "SHT_NOTE"},
    {SHT_NOBITS, "SHT_NOBITS"},
    {SHT_REL, "SHT_REL"},
    {SHT_SHLIB, "SHT_SHLIB"},
    {SHT_DYNSYM, "SHT_DYNSYM"},
    {SHT_INIT_ARRAY, "SHT_INIT_ARRAY"},
    {SHT_FINI_ARRAY, "SHT_FINI_ARRAY"},
    {SHT_PREINIT_ARRAY, "SHT_PREINIT_ARRAY"},
    {SHT_GROUP, "SHT_GROUP"},
    {SHT_SYMTAB_SHNDX, "SHT_SYMTAB_SHNDX"},
    {SHT_NUM, "SHT_NUM"},
    {SHT_LOOS, "SHT_LOOS"},
    {SHT_GNU_ATTRIBUTES, "SHT_GNU_ATTRIBUTES"},
    {SHT_GNU_HASH, "SHT_GNU_HASH"},
    {SHT_GNU_LIBLIST, "SHT_GNU_LIBLIST"},
    {SHT_CHECKSUM, "SHT_CHECKSUM"},
    {SHT_LOSUNW, "SHT_LOSUNW"},
    {SHT_SUNW_move, "SHT_SUNW_move"},
    {SHT_SUNW_COMDAT, "SHT_SUNW_COMDAT"},
    {SHT_SUNW_syminfo, "SHT_SUNW_syminfo"},
    {SHT_GNU_verdef, "SHT_GNU_verdef"},
    {SHT_GNU_verneed, "SHT_GNU_verneed"},
    {SHT_GNU_versym, "SHT_GNU_versym"}};

std::string ShowSHT(Elf_Word sh_type) {
    if (SHTToStr.contains(sh_type)) {
        return SHTToStr.at(sh_type);
    } else {
        LOG(FATAL) << "Unknown type: " << HexString(sh_type);
    }
}

Elf_Word ReadSHT(std::string str) {
    Elf_Word sh_type = 0;
    static const auto StrToSHT = InvertMap(SHTToStr);
    CHECK(StrToSHT.contains(str));
    return StrToSHT.at(str);
}

const std::map<Elf_Half, std::string> ELFTypeToStr = {
    {ET_NONE, "ET_NONE"}, {ET_REL, "ET_REL"},   {ET_EXEC, "ET_EXEC"},
    {ET_DYN, "ET_DYN"},   {ET_CORE, "ET_CORE"}, {ET_NUM, "ET_NUM"},
    {ET_LOOS, "ET_LOOS"}, {ET_HIOS, "ET_HIOS"}};

std::string ShowEType(Elf_Half e_type) {
    if (ELFTypeToStr.contains(e_type)) {
        return ELFTypeToStr.at(e_type);
    } else {
        LOG(FATAL) << "Unknown type: " << HexString(e_type);
    }
}

Elf_Half ReadEType(std::string str) {
    Elf_Half e_type = 0;
    static const auto StrToELFType = InvertMap(ELFTypeToStr);
    CHECK(StrToELFType.contains(str));
    return StrToELFType.at(str);
}

const std::map<Elf_Half, std::string> ELFMachineToStr = {
    {EM_NONE, "EM_NONE"},
    {EM_M32, "EM_M32"},
    {EM_SPARC, "EM_SPARC"},
    {EM_386, "EM_386"},
    {EM_68K, "EM_68K"},
    {EM_88K, "EM_88K"},
    {EM_IAMCU, "EM_IAMCU"},
    {EM_860, "EM_860"},
    {EM_MIPS, "EM_MIPS"},
    {EM_S370, "EM_S370"},
    {EM_MIPS_RS3_LE, "EM_MIPS_RS3_LE"},
    {EM_PARISC, "EM_PARISC"},
    {EM_VPP500, "EM_VPP500"},
    {EM_SPARC32PLUS, "EM_SPARC32PLUS"},
    {EM_960, "EM_960"},
    {EM_PPC, "EM_PPC"},
    {EM_PPC64, "EM_PPC64"},
    {EM_S390, "EM_S390"},
    {EM_SPU, "EM_SPU"},
    {EM_V800, "EM_V800"},
    {EM_FR20, "EM_FR20"},
    {EM_RH32, "EM_RH32"},
    {EM_RCE, "EM_RCE"},
    {EM_ARM, "EM_ARM"},
    {EM_FAKE_ALPHA, "EM_FAKE_ALPHA"},
    {EM_SH, "EM_SH"},
    {EM_SPARCV9, "EM_SPARCV9"},
    {EM_TRICORE, "EM_TRICORE"},
    {EM_ARC, "EM_ARC"},
    {EM_H8_300, "EM_H8_300"},
    {EM_H8_300H, "EM_H8_300H"},
    {EM_H8S, "EM_H8S"},
    {EM_H8_500, "EM_H8_500"},
    {EM_IA_64, "EM_IA_64"},
    {EM_MIPS_X, "EM_MIPS_X"},
    {EM_COLDFIRE, "EM_COLDFIRE"},
    {EM_68HC12, "EM_68HC12"},
    {EM_MMA, "EM_MMA"},
    {EM_PCP, "EM_PCP"},
    {EM_NCPU, "EM_NCPU"},
    {EM_NDR1, "EM_NDR1"},
    {EM_STARCORE, "EM_STARCORE"},
    {EM_ME16, "EM_ME16"},
    {EM_ST100, "EM_ST100"},
    {EM_TINYJ, "EM_TINYJ"},
    {EM_X86_64, "EM_X86_64"},
    {EM_PDSP, "EM_PDSP"},
    {EM_PDP10, "EM_PDP10"},
    {EM_PDP11, "EM_PDP11"},
    {EM_FX66, "EM_FX66"},
    {EM_ST9PLUS, "EM_ST9PLUS"},
    {EM_ST7, "EM_ST7"},
    {EM_68HC16, "EM_68HC16"},
    {EM_68HC11, "EM_68HC11"},
    {EM_68HC08, "EM_68HC08"},
    {EM_68HC05, "EM_68HC05"},
    {EM_SVX, "EM_SVX"},
    {EM_ST19, "EM_ST19"},
    {EM_VAX, "EM_VAX"},
    {EM_CRIS, "EM_CRIS"},
    {EM_JAVELIN, "EM_JAVELIN"},
    {EM_FIREPATH, "EM_FIREPATH"},
    {EM_ZSP, "EM_ZSP"},
    {EM_MMIX, "EM_MMIX"},
    {EM_HUANY, "EM_HUANY"},
    {EM_PRISM, "EM_PRISM"},
    {EM_AVR, "EM_AVR"},
    {EM_FR30, "EM_FR30"},
    {EM_D10V, "EM_D10V"},
    {EM_D30V, "EM_D30V"},
    {EM_V850, "EM_V850"},
    {EM_M32R, "EM_M32R"},
    {EM_MN10300, "EM_MN10300"},
    {EM_MN10200, "EM_MN10200"},
    {EM_PJ, "EM_PJ"},
    {EM_OPENRISC, "EM_OPENRISC"},
    {EM_ARC_COMPACT, "EM_ARC_COMPACT"},
    {EM_XTENSA, "EM_XTENSA"},
    {EM_VIDEOCORE, "EM_VIDEOCORE"},
    {EM_TMM_GPP, "EM_TMM_GPP"},
    {EM_NS32K, "EM_NS32K"},
    {EM_TPC, "EM_TPC"},
    {EM_SNP1K, "EM_SNP1K"},
    {EM_ST200, "EM_ST200"},
    {EM_IP2K, "EM_IP2K"},
    {EM_MAX, "EM_MAX"},
    {EM_CR, "EM_CR"},
    {EM_F2MC16, "EM_F2MC16"},
    {EM_MSP430, "EM_MSP430"},
    {EM_BLACKFIN, "EM_BLACKFIN"},
    {EM_SE_C33, "EM_SE_C33"},
    {EM_SEP, "EM_SEP"},
    {EM_ARCA, "EM_ARCA"},
    {EM_UNICORE, "EM_UNICORE"},
    {EM_EXCESS, "EM_EXCESS"},
    {EM_DXP, "EM_DXP"},
    {EM_ALTERA_NIOS2, "EM_ALTERA_NIOS2"},
    {EM_CRX, "EM_CRX"},
    {EM_XGATE, "EM_XGATE"},
    {EM_C166, "EM_C166"},
    {EM_M16C, "EM_M16C"},
    {EM_DSPIC30F, "EM_DSPIC30F"},
    {EM_CE, "EM_CE"},
    {EM_M32C, "EM_M32C"},
    {EM_TSK3000, "EM_TSK3000"},
    {EM_RS08, "EM_RS08"},
    {EM_SHARC, "EM_SHARC"},
    {EM_ECOG2, "EM_ECOG2"},
    {EM_SCORE7, "EM_SCORE7"},
    {EM_DSP24, "EM_DSP24"},
    {EM_VIDEOCORE3, "EM_VIDEOCORE3"},
    {EM_LATTICEMICO32, "EM_LATTICEMICO32"},
    {EM_SE_C17, "EM_SE_C17"},
    {EM_TI_C6000, "EM_TI_C6000"},
    {EM_TI_C2000, "EM_TI_C2000"},
    {EM_TI_C5500, "EM_TI_C5500"},
    {EM_TI_ARP32, "EM_TI_ARP32"},
    {EM_TI_PRU, "EM_TI_PRU"},
    {EM_MMDSP_PLUS, "EM_MMDSP_PLUS"},
    {EM_CYPRESS_M8C, "EM_CYPRESS_M8C"},
    {EM_R32C, "EM_R32C"},
    {EM_TRIMEDIA, "EM_TRIMEDIA"},
    {EM_QDSP6, "EM_QDSP6"},
    {EM_8051, "EM_8051"},
    {EM_STXP7X, "EM_STXP7X"},
    {EM_NDS32, "EM_NDS32"},
    {EM_ECOG1X, "EM_ECOG1X"},
    {EM_MAXQ30, "EM_MAXQ30"},
    {EM_XIMO16, "EM_XIMO16"},
    {EM_MANIK, "EM_MANIK"},
    {EM_CRAYNV2, "EM_CRAYNV2"},
    {EM_RX, "EM_RX"},
    {EM_METAG, "EM_METAG"},
    {EM_MCST_ELBRUS, "EM_MCST_ELBRUS"},
    {EM_ECOG16, "EM_ECOG16"},
    {EM_CR16, "EM_CR16"},
    {EM_ETPU, "EM_ETPU"},
    {EM_SLE9X, "EM_SLE9X"},
    {EM_L10M, "EM_L10M"},
    {EM_K10M, "EM_K10M"},
    {EM_AARCH64, "EM_AARCH64"},
    {EM_AVR32, "EM_AVR32"},
    {EM_STM8, "EM_STM8"},
    {EM_TILE64, "EM_TILE64"},
    {EM_TILEPRO, "EM_TILEPRO"},
    {EM_MICROBLAZE, "EM_MICROBLAZE"},
    {EM_CUDA, "EM_CUDA"},
    {EM_TILEGX, "EM_TILEGX"},
    {EM_CLOUDSHIELD, "EM_CLOUDSHIELD"},
    {EM_COREA_1ST, "EM_COREA_1ST"},
    {EM_COREA_2ND, "EM_COREA_2ND"},
    {EM_ARC_COMPACT2, "EM_ARC_COMPACT2"},
    {EM_OPEN8, "EM_OPEN8"},
    {EM_RL78, "EM_RL78"},
    {EM_VIDEOCORE5, "EM_VIDEOCORE5"},
    {EM_78KOR, "EM_78KOR"},
    {EM_56800EX, "EM_56800EX"},
    {EM_BA1, "EM_BA1"},
    {EM_BA2, "EM_BA2"},
    {EM_XCORE, "EM_XCORE"},
    {EM_MCHP_PIC, "EM_MCHP_PIC"},
    {EM_KM32, "EM_KM32"},
    {EM_KMX32, "EM_KMX32"},
    {EM_EMX16, "EM_EMX16"},
    {EM_EMX8, "EM_EMX8"},
    {EM_KVARC, "EM_KVARC"},
    {EM_CDP, "EM_CDP"},
    {EM_COGE, "EM_COGE"},
    {EM_COOL, "EM_COOL"},
    {EM_NORC, "EM_NORC"},
    {EM_CSR_KALIMBA, "EM_CSR_KALIMBA"},
    {EM_Z80, "EM_Z80"},
    {EM_VISIUM, "EM_VISIUM"},
    {EM_FT32, "EM_FT32"},
    {EM_MOXIE, "EM_MOXIE"},
    {EM_AMDGPU, "EM_AMDGPU"},
    {EM_RISCV, "EM_RISCV"},
    {EM_BPF, "EM_BPF"},
    {EM_CSKY, "EM_CSKY"}};

std::string ShowEMachine(Elf_Half e_machine) {
    if (ELFMachineToStr.contains(e_machine)) {
        return ELFMachineToStr.at(e_machine);
    } else {
        LOG(FATAL) << "Unknown type: " << HexString(e_machine);
    }
}

Elf_Half ReadEMachine(std::string str) {
    Elf_Half e_machine = 0;
    static const auto StrToELFMachine = InvertMap(ELFMachineToStr);
    CHECK(StrToELFMachine.contains(str));
    return StrToELFMachine.at(str);
}

const std::map<Elf_Word, std::string> PhdrFlagToStr = {
    {(1 << 0), "PF_X"}, {(1 << 1), "PF_W"}, {(1 << 2), "PF_R"}};

std::vector<std::string> ShowPhdrFlags(Elf_Word p_flags) {
    std::vector<std::string> ret;
    for (const auto& [f, s] : PhdrFlagToStr) {
        if (f & p_flags) {
            ret.emplace_back(s);
            p_flags ^= f;
        }
    }
    if (p_flags) {
        ret.emplace_back(HexString(p_flags));
    }
    return ret;
}

Elf_Word ReadPhdrFlags(std::vector<std::string> str) {
    Elf_Word flags = 0;
    static const auto StrToPhdrFlag = InvertMap(PhdrFlagToStr);
    for (const auto& s : str) {
        CHECK(StrToPhdrFlag.contains(s));
        flags |= StrToPhdrFlag.at(s);
    }
    return flags;
}

const std::map<Elf_Word, std::string> PhdrTypeToStr = {
    {PT_NULL, "PT_NULL"},
    {PT_LOAD, "PT_LOAD"},
    {PT_DYNAMIC, "PT_DYNAMIC"},
    {PT_INTERP, "PT_INTERP"},
    {PT_NOTE, "PT_NOTE"},
    {PT_SHLIB, "PT_SHLIB"},
    {PT_PHDR, "PT_PHDR"},
    {PT_TLS, "PT_TLS"},
    {PT_NUM, "PT_NUM"},
    {PT_LOOS, "PT_LOOS"},
    {PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME"},
    {PT_GNU_STACK, "PT_GNU_STACK"},
    {PT_GNU_RELRO, "PT_GNU_RELRO"},
    {PT_GNU_PROPERTY, "PT_GNU_PROPERTY"}};

std::string ShowPhdrType(Elf_Word type) {
    if (PhdrTypeToStr.contains(type)) {
        return PhdrTypeToStr.at(type);
    } else {
        LOG(FATAL) << "Unknown type: " << HexString(type, 8);
    }
}

Elf_Word ReadPhdrType(std::string str) {
    static auto str_to_phdr_type = InvertMap(PhdrTypeToStr);
    if (str_to_phdr_type.contains(str)) {
        return str_to_phdr_type[str];
    } else {
        LOG(FATAL) << "Unknown type: " << str;
    }
}

std::ostream& operator<<(std::ostream& os, const Elf_Rel& r) {
    os << "Elf_Rela{r_offset=" << SOLD_LOG_32BITS(r.r_offset)
       << ", r_info=" << SOLD_LOG_32BITS(r.r_info)
       << ", ELF_R_SYM(r.r_info)=" << SOLD_LOG_16BITS(ELF_R_SYM(r.r_info))
       << ", ELF_R_TYPE(r.r_info)=" << ShowRelocationType(ELF_R_TYPE(r.r_info))
       << ", r_addend=" << SOLD_LOG_32BITS(r.r_addend) << "}";
    return os;
}

bool is_special_ver_ndx(Elf64_Versym versym) {
    return (versym == VER_NDX_LOCAL || versym == VER_NDX_GLOBAL);
}

std::string special_ver_ndx_to_str(Elf64_Versym versym) {
    if (versym == VER_NDX_LOCAL) {
        return std::string("VER_NDX_LOCAL");
    } else if (versym == VER_NDX_GLOBAL) {
        return std::string("VER_NDX_GLOBAL");
    } else if (versym == NO_VERSION_INFO) {
        return std::string("NO_VERSION_INFO");
    } else {
        LOG(FATAL) << "This versym (= " << versym << ") is not special.";
        exit(1);
    }
}

uint64_t HexUInt(std::string str) {
    CHECK(str.starts_with("0x"));
    CHECK(str.size() > 2);
    uint64_t ret = 0;
    std::stringstream ss(str.substr(2));
    ss >> std::hex;
    ss >> ret;
    return ret;
}

// Copy from sysdeps/generic/unwind-pe.h in glibc
const char* read_uleb128(const char* p, uint32_t* val) {
    unsigned int shift = 0;
    unsigned char byte;
    uint32_t result;

    result = 0;
    do {
        byte = *p++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);

    *val = result;
    return p;
}

// Copy from sysdeps/generic/unwind-pe.h in glibc
const char* read_sleb128(const char* p, int32_t* val) {
    unsigned int shift = 0;
    unsigned char byte;
    int32_t result;

    result = 0;
    do {
        byte = *p++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);

    /* Sign-extend a negative value.  */
    if (shift < 8 * sizeof(result) && (byte & 0x40) != 0)
        result |= -(1L << shift);

    *val = (int32_t)result;
    return p;
}

// Copy from sysdeps/generic/unwind-pe.h in glibc
typedef unsigned sold_Unwind_Internal_Ptr
    __attribute__((__mode__(__pointer__)));
#define DW_EH_PE_indirect 0x80

const char* read_encoded_value_with_base(unsigned char encoding,
                                         sold_Unwind_Ptr base, const char* p,
                                         uint32_t* val) {
    union unaligned {
        void* ptr;
        unsigned u2 __attribute__((mode(HI)));
        unsigned u4 __attribute__((mode(SI)));
        unsigned u8 __attribute__((mode(DI)));
        signed s2 __attribute__((mode(HI)));
        signed s4 __attribute__((mode(SI)));
        signed s8 __attribute__((mode(DI)));
    } __attribute__((__packed__));

    union unaligned* u = (union unaligned*)p;
    sold_Unwind_Internal_Ptr result;

    if (encoding == DW_EH_PE_aligned) {
        sold_Unwind_Internal_Ptr a = (sold_Unwind_Internal_Ptr)p;
        a = (a + sizeof(void*) - 1) & -sizeof(void*);
        result = *(sold_Unwind_Internal_Ptr*)a;
        p = (char*)(a + sizeof(void*));
    } else {
        switch (encoding & 0x0f) {
            case DW_EH_PE_absptr:
                result = (sold_Unwind_Internal_Ptr)u->ptr;
                p += sizeof(void*);
                break;

            case DW_EH_PE_uleb128: {
                uint32_t tmp;
                p = read_uleb128(p, &tmp);
                result = (sold_Unwind_Internal_Ptr)tmp;
            } break;

            case DW_EH_PE_sleb128: {
                int32_t tmp;
                p = read_sleb128(p, &tmp);
                result = (sold_Unwind_Internal_Ptr)tmp;
            } break;

            case DW_EH_PE_udata2:
                result = u->u2;
                p += 2;
                break;
            case DW_EH_PE_udata4:
                result = u->u4;
                p += 4;
                break;
            case DW_EH_PE_udata8:
                result = u->u8;
                p += 8;
                break;

            case DW_EH_PE_sdata2:
                result = u->s2;
                p += 2;
                break;
            case DW_EH_PE_sdata4:
                result = u->s4;
                p += 4;
                break;
            case DW_EH_PE_sdata8:
                result = u->s8;
                p += 8;
                break;
            default:
                LOG(FATAL) << SOLD_LOG_8BITS(encoding & 0x0f);
        }

        if (result != 0) {
            result += ((encoding & 0x70) == DW_EH_PE_pcrel
                           ? (sold_Unwind_Internal_Ptr)u
                           : base);
            if (encoding & DW_EH_PE_indirect)
                result = *(sold_Unwind_Internal_Ptr*)result;
        }
    }

    *val = result;
    return p;
}

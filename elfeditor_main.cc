#include <getopt.h>
#include <glog/logging.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "elf_binary.h"

void print_help(std::ostream& os) {
    os << R"(Usage:
elfeditor help                             Show this message.
elfeditor dump [INPUT] [JSON]              Dump [INPUT] to [JSON].
elfeditor apply [INPUT] [OUTPUT] [JSON]    Apply [JSON] to [INPUT] and save to [OUTPUT].
elfeditor show [INPUT]                     Show [INPUT] in JSON format
elfeditor edit [INPUT] [OUTPUT]            dump + apply. It launches editor automatically.
-e, --editor                               Editor to edit JSON in edit subcommand.
)" << std::endl;
}

void dump(const std::string input_, const std::string json_) {
    auto input = ReadELF(input_);

    nlohmann::json json;

    // ELF Header
    {
        const Elf_Ehdr* ehdr = input->ehdr();
        for (int i = 0; i < EI_NIDENT; i++) {
            json["ehdr"]["e_ident"][i] = HexString(ehdr->e_ident[i]);
        }
        json["ehdr"]["e_type"] = ShowEType(ehdr->e_type);
        json["ehdr"]["e_machine"] = ShowEMachine(ehdr->e_machine);
        json["ehdr"]["e_version"] = HexString(ehdr->e_version);
        json["ehdr"]["e_entry"] = HexString(ehdr->e_entry);
        json["ehdr"]["e_phoff"] = HexString(ehdr->e_phoff);
        json["ehdr"]["e_shoff"] = HexString(ehdr->e_shoff);
        json["ehdr"]["e_flags"] = HexString(ehdr->e_flags);
        json["ehdr"]["e_ehsize"] = HexString(ehdr->e_ehsize);
        json["ehdr"]["e_phentsize"] = HexString(ehdr->e_phentsize);
        json["ehdr"]["e_phnum"] = HexString(ehdr->e_phnum);
        json["ehdr"]["e_shentsize"] = HexString(ehdr->e_shentsize);
        json["ehdr"]["e_shnum"] = HexString(ehdr->e_shnum);
        json["ehdr"]["e_shstrndx"] = HexString(ehdr->e_shstrndx);
    }

    // Program Headers
    for (int i = 0; i < input->phdrs().size(); i++) {
        const Elf_Phdr* phdr = input->phdrs()[i];
        json["phdr"][i]["p_type"] = ShowPhdrType(phdr->p_type);
        json["phdr"][i]["p_vaddr"] = HexString(phdr->p_vaddr);
        json["phdr"][i]["p_paddr"] = HexString(phdr->p_paddr);
        json["phdr"][i]["p_filesz"] = HexString(phdr->p_filesz);
        json["phdr"][i]["p_memsz"] = HexString(phdr->p_memsz);
        json["phdr"][i]["p_offset"] = HexString(phdr->p_offset);
        json["phdr"][i]["p_flags"] = ShowPhdrFlags(phdr->p_flags);
        json["phdr"][i]["p_align"] = HexString(phdr->p_align);
        if (ShowPhdrType(phdr->p_type) == "PT_INTERP") {
            json["phdr"][i]["contents"] = EscapedString(
                input->GetContents(phdr->p_offset, phdr->p_filesz));
        } else if (ShowPhdrType(phdr->p_type) == "PT_DYNAMIC") {
            for (int j = 0; j < input->dyns().size(); j++) {
                Elf_Dyn* dyn = input->dyns()[j];
                json["phdr"][i]["contents"][j]["d_tag"] = ShowDT(dyn->d_tag);
                json["phdr"][i]["contents"][j]["d_un.d_val"] =
                    HexString(dyn->d_un.d_val);
            }
        }
    }

    // Section Headers
    for (int i = 0; i < input->shdrs().size(); i++) {
        const Elf_Shdr* shdr = input->shdrs()[i];
        json["shdr"][i]["sh_name"] = HexString(shdr->sh_name);
        json["shdr"][i]["sh_type"] = ShowSHT(shdr->sh_type);
        json["shdr"][i]["sh_flags"] = ShowShdrFlags(shdr->sh_flags);
        json["shdr"][i]["sh_addr"] = HexString(shdr->sh_addr);
        json["shdr"][i]["sh_offset"] = HexString(shdr->sh_offset);
        json["shdr"][i]["sh_size"] = HexString(shdr->sh_size);
        json["shdr"][i]["sh_link"] = HexString(shdr->sh_link);
        json["shdr"][i]["sh_info"] = HexString(shdr->sh_info);
        json["shdr"][i]["sh_addralign"] = HexString(shdr->sh_addralign);
        json["shdr"][i]["sh_entsize"] = HexString(shdr->sh_entsize);
    }

    std::ofstream ofs(json_);
    CHECK(ofs);
    ofs << json.dump(2);
}

void apply(const std::string input_, const std::string output_,
           const std::string json_) {
    auto input = ReadELF(input_);
    std::ifstream ifs(json_);
    CHECK(ifs);
    nlohmann::json json;
    ifs >> json;

    if (json.contains("ehdr")) {
        auto ehdr = input->ehdr_mut();
        auto json_ehdr = json["ehdr"];
        for (int i = 0; i < EI_NIDENT; i++) {
            ehdr->e_ident[i] = HexUInt(json_ehdr["e_ident"][i]);
        }
        ehdr->e_type = ReadEType(json_ehdr["e_type"]);
        ehdr->e_machine = ReadEMachine(json_ehdr["e_machine"]);
        ehdr->e_version = HexUInt(json_ehdr["e_version"]);
        ehdr->e_entry = HexUInt(json_ehdr["e_entry"]);
        ehdr->e_phoff = HexUInt(json_ehdr["e_phoff"]);
        ehdr->e_shoff = HexUInt(json_ehdr["e_shoff"]);
        ehdr->e_flags = HexUInt(json_ehdr["e_flags"]);
        ehdr->e_ehsize = HexUInt(json_ehdr["e_ehsize"]);
        ehdr->e_phentsize = HexUInt(json_ehdr["e_phentsize"]);
        ehdr->e_phnum = HexUInt(json_ehdr["e_phnum"]);
        ehdr->e_shentsize = HexUInt(json_ehdr["e_shentsize"]);
        ehdr->e_shnum = HexUInt(json_ehdr["e_shnum"]);
        ehdr->e_shstrndx = HexUInt(json_ehdr["e_shstrndx"]);
    }

    if (json.contains("phdr")) {
        CHECK(json["phdr"].size() == input->phdrs().size());
        for (int i = 0; i < input->phdrs().size(); i++) {
            auto phdr = input->phdrs()[i];
            auto json_phdr = json["phdr"][i];
            phdr->p_type = ReadPhdrType(json_phdr["p_type"]);
            phdr->p_vaddr = HexUInt(json_phdr["p_vaddr"]);
            phdr->p_paddr = HexUInt(json_phdr["p_paddr"]);
            phdr->p_filesz = HexUInt(json_phdr["p_filesz"]);
            phdr->p_memsz = HexUInt(json_phdr["p_memsz"]);
            phdr->p_offset = HexUInt(json_phdr["p_offset"]);

            std::vector<std::string> flags;
            for (const auto& f : json_phdr["p_flags"]) {
                flags.emplace_back(f.get<std::string>());
            }
            phdr->p_flags = ReadPhdrFlags(flags);

            phdr->p_align = HexUInt(json_phdr["p_align"]);

            if (ShowPhdrType(phdr->p_type) == "PT_INTERP") {
                input->SetContents(HexUInt(json_phdr["p_offset"]),
                                   GetChars(json_phdr["contents"]));
            } else if (ShowPhdrType(phdr->p_type) == "PT_DYNAMIC") {
                CHECK_EQ(json_phdr["contents"].size(), input->dyns().size());
                for (int j = 0; j < json_phdr["contents"].size(); j++) {
                    input->dyns()[j]->d_tag =
                        ReadDT(json_phdr["contents"][j]["d_tag"]);
                    input->dyns()[j]->d_un.d_val =
                        HexUInt(json_phdr["contents"][j]["d_un.d_val"]);
                }
            }
        }
    }

    if (json.contains("shdr")) {
        CHECK(json["shdr"].size() == input->shdrs().size());
        for (int i = 0; i < input->shdrs().size(); i++) {
            auto shdr = input->shdrs()[i];
            auto json_shdr = json["shdr"][i];
            shdr->sh_name = HexUInt(json_shdr["sh_name"]);
            shdr->sh_type = ReadSHT(json_shdr["sh_type"]);
            shdr->sh_flags = ReadShdrFlags(json_shdr["sh_flags"]);
            shdr->sh_addr = HexUInt(json_shdr["sh_addr"]);
            shdr->sh_offset = HexUInt(json_shdr["sh_offset"]);
            shdr->sh_size = HexUInt(json_shdr["sh_size"]);
            shdr->sh_link = HexUInt(json_shdr["sh_link"]);
            shdr->sh_addralign = HexUInt(json_shdr["sh_addralign"]);
            shdr->sh_entsize = HexUInt(json_shdr["sh_entsize"]);
        }
    }

    FILE* fp = fopen(output_.c_str(), "wb");
    WriteBuf(fp, input->head(), input->filesize());
    fclose(fp);
}

void edit(const std::string input, const std::string output,
          const std::string editor) {
    std::string json = std::tmpnam(nullptr);
    dump(input, json);

    std::string cmd = editor + " " + json;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        LOG(WARNING) << cmd << " returns " << ret;
    }

    apply(input, output, json);
    std::filesystem::remove(json);
}

void show(const std::string input, const std::string editor) {
    std::string json = std::tmpnam(nullptr);
    dump(input, json);

    std::string cmd = editor + " " + json;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        LOG(WARNING) << cmd << " returns " << ret;
    }

    std::filesystem::remove(json);
}

enum Mode { Dump, Apply, Edit, Show };

int main(int argc, char* const argv[]) {
    google::InitGoogleLogging(argv[0]);

    static option long_options[] = {
        {"editor", required_argument, nullptr, 'e'},
        {0, 0, 0, 0},
    };

    Mode mode;
    std::string input;
    std::string output;
    std::string json;

    if (argc == 2 && std::string(argv[1]) == "help") {
        print_help(std::cout);
        return 0;
    } else if (argc == 4 && std::string(argv[1]) == "dump") {
        mode = Mode::Dump;
        input = argv[2];
        json = argv[3];
        argc -= 2;
        argv += 2;
    } else if (argc == 5 && std::string(argv[1]) == "apply") {
        mode = Mode::Apply;
        input = argv[2];
        output = argv[3];
        json = argv[4];
        argc -= 3;
        argv += 3;
    } else if (argc == 4 && std::string(argv[1]) == "edit") {
        mode = Mode::Edit;
        input = argv[2];
        output = argv[3];
        argc -= 2;
        argv += 2;
    } else if (argc == 3 && std::string(argv[1]) == "show") {
        mode = Mode::Show;
        input = argv[2];
        argc -= 1;
        argv += 1;
    } else {
        std::cerr << "argc = " << argc << std::endl;
        print_help(std::cerr);
        return 1;
    }

    std::string editor =
        std::getenv("EDITOR") == nullptr ? "vi" : std::getenv("EDITOR");

    int opt;
    while ((opt = getopt_long(argc, argv, "e:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'e':
                editor = optarg;
                break;
        }
    }

    if (!std::filesystem::exists(input)) {
        std::cerr << input << " does not exist." << std::endl;
    }

    switch (mode) {
        case Mode::Dump:
            dump(input, json);
            break;
        case Mode::Apply:
            apply(input, output, json);
            break;
        case Mode::Edit:
            edit(input, output, editor);
            break;
        case Mode::Show:
            show(input, editor);
            break;
    }
    return 0;
}

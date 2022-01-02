#include <getopt.h>
#include <glog/logging.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "elf_binary.h"

void print_help(std::ostream& os) {
    os << R"(Options:
-h, --help    Show this help message and exit
-d, --dump    Dump PHDRs of input_elf as json file. This needs --input_elf and --json
-e, --edit    Edit PHDRs following json file. This needs --input_elf, --output_elf and --json.
-i, --input_elf
-o, --output_elf
-j, --json
)" << std::endl;
}

void dump(const std::string input_elf_, const std::string json_) {
    auto input_elf = ReadELF(input_elf_);

    nlohmann::json json;
    for (int i = 0; i < input_elf->phdrs().size(); i++) {
        const Elf_Phdr* phdr = input_elf->phdrs()[i];
        json["phdr"][i]["p_type"] = ShowPhdrType(phdr->p_type);
        json["phdr"][i]["p_vaddr"] = HexString(phdr->p_vaddr);
        json["phdr"][i]["p_paddr"] = HexString(phdr->p_paddr);
        json["phdr"][i]["p_filesz"] = HexString(phdr->p_filesz);
        json["phdr"][i]["p_memsz"] = HexString(phdr->p_memsz);
        json["phdr"][i]["p_flags"] = ShowPhdrFlags(phdr->p_flags);
        json["phdr"][i]["p_align"] = HexString(phdr->p_align);
    }

    std::ofstream ofs(json_);
    std::cout << json.dump(2);
    ofs << json.dump(2);
}

void edit(const std::string input_elf_, const std::string output_elf_,
          const std::string json_) {
    auto input_elf = ReadELF(input_elf_);
    std::ifstream ifs(json_);
    CHECK(ifs);
    nlohmann::json json;
    ifs >> json;

    if (json.contains("phdr")) {
        CHECK(json["phdr"].size() == input_elf->phdrs().size());
        for (int i = 0; i < input_elf->phdrs().size(); i++) {
            auto phdr = input_elf->phdrs()[i];
            auto json_phdr = json["phdr"][i];
            phdr->p_type = ReadPhdrType(json_phdr["p_type"]);
            phdr->p_vaddr = HexUInt(json_phdr["p_vaddr"]);
            phdr->p_paddr = HexUInt(json_phdr["p_paddr"]);
            phdr->p_filesz = HexUInt(json_phdr["p_filesz"]);
            phdr->p_memsz = HexUInt(json_phdr["p_memsz"]);

            std::vector<std::string> flags;
            for (const auto& f : json_phdr["p_flags"]) {
                flags.emplace_back(f.get<std::string>());
            }
            phdr->p_flags = ReadPhdrFlags(flags);

            phdr->p_align = HexUInt(json_phdr["p_align"]);
        }
    }

    FILE* fp = fopen(output_elf_.c_str(), "wb");
    WriteBuf(fp, input_elf->head(), input_elf->filesize());
    fclose(fp);
}

int main(int argc, char* const argv[]) {
    google::InitGoogleLogging(argv[0]);

    static option long_options[] = {
        {"help", no_argument, nullptr, 'h'},
        {"dump", no_argument, nullptr, 'd'},
        {"edit", no_argument, nullptr, 'e'},
        {"input_elf", required_argument, nullptr, 'i'},
        {"output_elf", required_argument, nullptr, 'o'},
        {"json", required_argument, nullptr, 'j'},
        {0, 0, 0, 0},
    };

    bool is_dump = false;
    bool is_edit = false;
    std::string input_elf;
    std::string output_elf;
    std::string json;

    int opt;
    while ((opt = getopt_long(argc, argv, "hd:e:i:o:j:", long_options,
                              nullptr)) != -1) {
        switch (opt) {
            case 'h':
                print_help(std::cout);
                return 0;
            case '?':
                print_help(std::cerr);
                return 1;
            case 'd':
                is_dump = true;
                break;
            case 'e':
                is_edit = true;
                break;
            case 'i':
                input_elf = optarg;
                break;
            case 'o':
                output_elf = optarg;
                break;
            case 'j':
                json = optarg;
                break;
        }
    }

    CHECK(is_edit ^ is_dump) << "You must specify one of --edit or --dump.";

    if (is_dump) {
        CHECK(!input_elf.empty());
        CHECK(!json.empty());
        dump(input_elf, json);
    } else {
        CHECK(!input_elf.empty());
        CHECK(!output_elf.empty());
        CHECK(!json.empty());
        edit(input_elf, output_elf, json);
    }
    return 0;
}

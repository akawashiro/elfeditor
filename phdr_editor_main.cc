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

void dump(const std::string input_elf_, std::string phdr_json_) {
    auto input_elf = ReadELF(input_elf_);

    nlohmann::json phdr_json;
    for (int i = 0; i < input_elf->phdrs().size(); i++) {
        const Elf_Phdr* phdr = input_elf->phdrs()[i];
        phdr_json[i]["p_type"] = ShowPhdrType(phdr->p_type);
        phdr_json[i]["p_vaddr"] = HexString(phdr->p_vaddr);
        phdr_json[i]["p_paddr"] = HexString(phdr->p_paddr);
        phdr_json[i]["p_filesz"] = HexString(phdr->p_filesz);
        phdr_json[i]["p_memsz"] = HexString(phdr->p_memsz);
        phdr_json[i]["p_flags"] = HexString(phdr->p_flags);
        phdr_json[i]["p_align"] = HexString(phdr->p_align);
    }

    std::ofstream ofs(phdr_json_);
    std::cout << phdr_json.dump(4);
    ofs << phdr_json.dump(4);
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
    std::string phdr_json;

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
                phdr_json = optarg;
                break;
        }
    }

    CHECK(is_edit ^ is_dump) << "You must specify one of --edit or --dump.";

    if (is_dump) {
        CHECK(!input_elf.empty());
        CHECK(!phdr_json.empty());
        dump(input_elf, phdr_json);
    } else {
        ;
    }
    return 0;
}

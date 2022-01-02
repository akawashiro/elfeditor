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
elf-editor help                             Show this message.
elf-editor dump [INPUT] [JSON]              Dump [INPUT] to [JSON].
elf-editor apply [INPUT] [OUTPUT] [JSON]     Apply [JSON] to [INPUT] and save to [OUTPUT].
elf-editor edit [INPUT] [OUTPUT]            dump + apply. It launches editor automatically.
-e, --editor                                Editor to edit JSON in edit subcommand.
)" << std::endl;
}

void dump(const std::string input_, const std::string json_) {
    auto input = ReadELF(input_);

    nlohmann::json json;
    for (int i = 0; i < input->phdrs().size(); i++) {
        const Elf_Phdr* phdr = input->phdrs()[i];
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

void apply(const std::string input_, const std::string output_,
           const std::string json_) {
    auto input = ReadELF(input_);
    std::ifstream ifs(json_);
    CHECK(ifs);
    nlohmann::json json;
    ifs >> json;

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

            std::vector<std::string> flags;
            for (const auto& f : json_phdr["p_flags"]) {
                flags.emplace_back(f.get<std::string>());
            }
            phdr->p_flags = ReadPhdrFlags(flags);

            phdr->p_align = HexUInt(json_phdr["p_align"]);
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
    system(cmd.c_str());

    apply(input, output, json);
    std::filesystem::remove(json);
}

enum Mode { Dump, Apply, Edit };

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
    }
    return 0;
}

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/table.h"

#include <vector>

namespace zeek::agent::table {

class FilesBase : public SnapshotTable {
protected:
    std::vector<filesystem::path> expandPaths(const std::vector<table::Where>& wheres);
};

class FilesListCommon : public FilesBase {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "files_list",
            .summary = "List files matching glob pattern",
            .description = R"(
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "path", .type = value::Type::Text, .summary = "", .mandatory_constraint = true },
                {.name = "type", .type = value::Type::Text, .summary = ""},
                {.name = "uid", .type = value::Type::Integer, .summary = ""},
                {.name = "gid", .type = value::Type::Integer, .summary = ""},
                {.name = "mode", .type = value::Type::Text, .summary = ""},
                {.name = "mtime", .type = value::Type::Integer, .summary = ""},
                {.name = "size", .type = value::Type::Integer, .summary = ""},
        }
            // clang-format on
        };
    }
};

class FilesLinesCommon : public FilesBase {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "files_lines",
            .summary = "Report lines of text files matching glob pattern, with leading and trailing whitespace stripped.",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "path", .type = value::Type::Text, .summary = "", .mandatory_constraint = true },
                {.name = "line", .type = value::Type::Integer, .summary = ""},
                {.name = "data", .type = value::Type::Blob, .summary = ""},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/table.h"

#include <string>
#include <utility>
#include <vector>

namespace zeek::agent::table {

class FilesBase : public SnapshotTable {
protected:
    std::pair<std::string, std::vector<filesystem::path>> expandPaths(const std::vector<table::Argument>& args);
};

class FilesListCommon : public FilesBase {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "files_list",
            .summary = "file system paths matching a pattern",
            .description = R"(
                The table provides a list of all files on the endpoint's file
                system that match a custom glob pattern. The pattern gets
                specified through a mandatory table parameter. For example, on
                a traditional Linux system, `SELECT * from
                files_list("/etc/init.d/*")` will fill the table with all files
                inside that directory. If you then watch for changes to that
                list, you'll be notified for any changes in system services.

                The list of files is generated at query time. The `pattern`
                glob needs to match on absolute file paths.
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "_pattern", .type = value::Type::Text, .summary = "glob matching all files of interest", .is_parameter = true },
                {.name = "path", .type = value::Type::Text, .summary = "full path" },
                {.name = "type", .type = value::Type::Text, .summary = "textual description of the path's type (e.g., `file`, `dir`, `socket`)"},
                {.name = "uid", .type = value::Type::Integer, .summary = "ID of user owning file"},
                {.name = "gid", .type = value::Type::Integer, .summary = "ID if group owning file"},
                {.name = "mode", .type = value::Type::Text, .summary = "octal permission mode"},
                {.name = "mtime", .type = value::Type::Integer, .summary = "time of last modification as seconds since epoch"},
                {.name = "size", .type = value::Type::Integer, .summary = "file size in bytes"},
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
            .summary = "line of selected ASCII files",
            .description = R"(
                The table returns lines from selected ASCII files as table
                rows. The files of interest get specified through a mandatory
                table parameter. At the time of query, the table reads in all
                matching files and returns one row per line, with any
                leading/trailing whitespace stripped. For example, `SELECT *
                FROM files_lines("/home/*/.ssh/authorized_keys")`, will return
                any SSH keys that users have authorized to access their
                accounts.`
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "_pattern", .type = value::Type::Text, .summary = "glob matching all files of interest", .is_parameter = true },
                {.name = "path", .type = value::Type::Text, .summary = "absolute path" },
                {.name = "number", .type = value::Type::Integer, .summary = "line number"},
                {.name = "content", .type = value::Type::Blob, .summary = "content of line"},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table

// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

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
            .platforms = { Platform::Darwin, Platform::Linux, Platform::Windows },
            .columns = {
                {.name = "_pattern", .type = value::Type::Text, .summary = "glob matching all files of interest", .is_parameter = true },
                {.name = "path", .type = value::Type::Text, .summary = "full path" },
                {.name = "type", .type = value::Type::Text, .summary = "textual description of the path's type (e.g., `file`, `dir`, `socket`)"},
                {.name = "uid", .type = value::Type::Count, .summary = "ID of user owning file"},
                {.name = "gid", .type = value::Type::Count, .summary = "ID if group owning file"},
                {.name = "mode", .type = value::Type::Text, .summary = "octal permission mode"},
                {.name = "mtime", .type = value::Type::Time, .summary = "time of last modification"},
                {.name = "size", .type = value::Type::Count, .summary = "file size in bytes"},
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
            .summary = "lines extracted from selected ASCII files",
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
                {.name = "number", .type = value::Type::Count, .summary = "line number"},
                {.name = "content", .type = value::Type::Blob, .summary = "content of line"},
        }
            // clang-format on
        };
    }
};

class FilesColumnsCommon : public FilesBase {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "files_columns",
            .summary = "columns extracted from selected ASCII files",
            .description = R"(
                The table returns columns extracted from selected ASCII files
                as a Zeek record of correspoding field values. At the time of
                query, the table reads in all relevant files line by line. It
                then splits each line into columns based on a delimiter string
                and returns the columns of interest.

                The files to read are specified through the 1st table
                parameter, which is a glob matching all relevant paths.

                The columns to extract from each line are specified through the
                2nd table parameter, which is a string containing a
                comma-separated list of tuples `$<N>:<type>`, where `<N>` is a
                column number (`$1` being the 1st column, `$2` the 2nd,
                etc.); and `<type>` is the type as which the value in that
                column will be parsed. Types can be: `blob`, `count`, `int`,
                `real`, `text`. As a special case, the column `$0` refers to
                whole line, without any processing.

                The column separator is specified by the 3rd table parameter.
                It can be either left empty for splitting on white-space, or a
                string to search for. If empty (which is the default), any
                whitespace at the beginning and end of a line is ignored as
                well.

                Finally, a 4th table parameter specifies a regular expression
                matching lines that are to be ignored. By default, this is set
                to lines starting with common comment prefixes (`#`, `;`). If
                this parameter is set to an empty string, no lines will be
                ignored.

                In the query result, `columns` will contain a JSON array with
                the selected values for each line. On the Zeek-side, this array
                will roll out into a Zeek `record`.

                Here's an example: `SELECT columns from
                files_columns("/etc/passwd", "$1:text,$3:count", ":")` splits
                `/etc/passwd` into its parts, and extracts the user name and ID
                for each line. (As `passwd` files may include comments lines,
                you could add a 4th parameter `"^ *#"` to ignore these.
                However, comments starting with `#` are already covered by the
                pattern that the 4th parameter uses by default, so it's not
                necessary.)
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "_pattern", .type = value::Type::Text, .summary = "glob matching all files of interest", .is_parameter = true },
                {.name = "_columns", .type = value::Type::Text, .summary = "specification of columns to extract", .is_parameter = true },
                {.name = "_separator", .type = value::Type::Text, .summary = "separator string to split columns; empty for whitespace", .is_parameter = true, .default_ = {""}},
                {.name = "_ignore", .type = value::Type::Text, .summary = "regular expression matching lines to ignore; empty to disable", .is_parameter = true, .default_ = {"^[ \\t]*([#;]|$)"}},
                {.name = "path", .type = value::Type::Text, .summary = "absolute path" },
                {.name = "number", .type = value::Type::Count, .summary = "line number in source file"},
                {.name = "columns", .type = value::Type::Record, .summary = "extracted columns"},
        }
            // clang-format on
        };
    }

    using Columns = std::vector<std::pair<int, value::Type>>;
    static Result<Columns> parseColumnsSpec(const std::string& spec);
};

} // namespace zeek::agent::table

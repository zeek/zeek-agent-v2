// Copyright (c) 2021 by t:he Zeek Project. See LICENSE for details.

#include "files.h"

#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "platform/platform.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <regex>

#include <Shlwapi.h>

using namespace zeek::agent::platform::windows;

namespace zeek::agent::table {

struct FindCloser {
    void operator()(HANDLE h) const { FindClose(h); }
};
using FindHandlePtr = std::unique_ptr<std::remove_pointer<HANDLE>::type, FindCloser>;

class FilesListWindows final : public FilesListCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;

private:
    std::vector<Value> buildFileRow(const std::string& pattern, const WIN32_FIND_DATAA& data) const;
};

class FilesLinesWindows final : public FilesLinesCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

class FilesColumnsWindows final : public FilesColumnsCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

namespace {
database::RegisterTable<FilesListWindows> _1;
database::RegisterTable<FilesLinesWindows> _2;
database::RegisterTable<FilesColumnsWindows> _3;
} // namespace

std::pair<std::string, std::vector<filesystem::path>> FilesBase::expandPaths(const std::vector<table::Argument>& args) {
    std::pair<std::string, std::vector<filesystem::path>> result;

    auto glob = Table::getArgument<std::string>(args, "_pattern");
    result.first = glob;

    for ( auto p : zeek::agent::glob(glob) )
        result.second.push_back(std::move(p));

    return result;
}

std::vector<std::vector<Value>> FilesListWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    auto [pattern, paths] = expandPaths(args);

    for ( const auto& p : paths ) {
        Value path = p.string();
        Value type;
        Value mode;
        Value mtime;
        Value size;

        std::error_code ec;
        auto status = filesystem::status(p, ec);
        if ( ec ) {
            ZEEK_AGENT_DEBUG("FilesListWindows", "Failed to get file status: {}", ec.message());
            continue;
        }

        mode = frmt("{:o}", static_cast<int64_t>(status.permissions()));
        switch ( status.type() ) {
            case filesystem::file_type::none:
            case filesystem::file_type::not_found:
            case filesystem::file_type::symlink:
            case filesystem::file_type::unknown: type = "other"; break;
            case filesystem::file_type::regular:
                type = "file";
                size = static_cast<int64_t>(filesystem::file_size(p, ec));
                if ( ec ) {
                    ZEEK_AGENT_DEBUG("FilesListWindows", "Failed to get file size: {}", ec.message());
                    continue;
                }
                break;
            case filesystem::file_type::directory: type = "dir"; break;
            case filesystem::file_type::block: type = "block"; break;
            case filesystem::file_type::character: type = "char"; break;
            case filesystem::file_type::fifo: type = "fifo"; break;
            case filesystem::file_type::socket: type = "socket"; break;
        }

        mtime = filesystem::last_write_time(p, ec);
        if ( ec ) {
            ZEEK_AGENT_DEBUG("FilesListWindows", "Failed to get file mtime: {}", ec.message());
            continue;
        }

        rows.push_back({pattern, path, type, {}, {}, mode, mtime, size});
    }

    return rows;
}

std::vector<std::vector<Value>> FilesLinesWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    auto [pattern, paths] = expandPaths(args);
    for ( const auto& p : paths ) {
        std::ifstream in(p);
        if ( in.fail() ) {
            // If file simply doesn't exist, we silently ignore the error.
            // Otherwise we add one row with `line` unset as an error indicator.
            if ( filesystem::exists(p) && ! filesystem::is_directory(p) )
                // TODO: this error doesn't actually work right. i copied it from the posix file
                // but i'm not sure it's being tested there either. the table requires 4 columns
                // but we're only inserting 3.
                rows.push_back({p.string(), {}, "<failed to open file>"});

            continue;
        }

        int64_t number = 0;
        std::string content;

        // TODO: should use a version of getline() that can abort at a given max-size.
        while ( std::getline(in, content) )
            rows.push_back({pattern, p.string(), ++number, trim(content)});

        in.close();
    }

    return rows;
}

std::vector<std::vector<Value>> FilesColumnsWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;
    // TODO: We don't have a way currently to preprocess column-spec and
    // ignore-expression ahead of time, so need to recompile it every time. The
    // problem is that there's not way to attach state to the current query.
    // Not sure how to do that, but in practice it probably doesn't matter much
    // anyways.

    auto& separator = Table::getArgument<std::string>(args, "_separator");

    auto& spec = Table::getArgument<std::string>(args, "_columns");
    auto columns = parseColumnsSpec(spec);
    if ( ! columns )
        throw table::PermanentContentError(frmt("invalid column specification for 'files_columns': {}", spec));

    auto& ignore = Table::getArgument<std::string>(args, "_ignore");
    std::optional<std::regex> ignore_regex;

    if ( ! ignore.empty() ) {
        try {
            ignore_regex = std::regex{ignore, std::regex::extended | std::regex::nosubs};
        } catch ( const std::regex_error& err ) {
            throw table::PermanentContentError(frmt("invalid ignore regex for 'files_columns': {}", ignore));
        }
    }

    auto [pattern, paths] = expandPaths(args);

    for ( const auto& p : paths ) {
        std::ifstream in(p);
        if ( in.fail() )
            // We silently ignore any errors. If the file doesn't exist, we
            // assume that's legitimate. For other errors, we don't have good
            // way to record them.
            continue;

        int64_t number = 0;
        std::string line;

        // TODO: should use a version of getline() that can abort at a given max-size.
        while ( std::getline(in, line) ) {
            std::smatch match;
            if ( ignore_regex && std::regex_search(line, match, ignore_regex.value()) )
                continue;

            std::vector<std::string> m;
            if ( ! separator.empty() )
                m = split(line, separator);
            else
                m = split(line);

            Record value;
            for ( const auto& [nr, type] : *columns ) {
                if ( nr == 0 )
                    value.emplace_back(stringToValue(line, type));
                else if ( nr >= 1 && nr <= m.size() )
                    value.emplace_back(stringToValue(m[nr - 1], type));
                else
                    value.emplace_back(std::monostate(), value::Type::Null);
            }

            rows.push_back({pattern, spec, separator, ignore, p.string(), ++number, std::move(value)});
        }

        in.close();
    }

    return rows;
}

} // namespace zeek::agent::table

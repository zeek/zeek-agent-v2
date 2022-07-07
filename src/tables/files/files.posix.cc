// Copyright (c) 2021 by t:he Zeek Project. See LICENSE for details.

#include "files.h"

#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/platform.h"

#include <variant>

#include <regex.h>

#include <sys/stat.h>

namespace zeek::agent::table {

class FilesListPosix : public FilesListCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

class FilesLinesPosix : public FilesLinesCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

class FilesColumnsPosix : public FilesColumnsCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

namespace {
database::RegisterTable<FilesListPosix> _1;
database::RegisterTable<FilesLinesPosix> _2;
database::RegisterTable<FilesColumnsPosix> _3;
} // namespace

std::pair<std::string, std::vector<filesystem::path>> FilesBase::expandPaths(const std::vector<table::Argument>& args) {
    std::pair<std::string, std::vector<filesystem::path>> result;

    auto glob = Table::getArgument<std::string>(args, "_pattern");
    result.first = glob;

    for ( auto p : platform::glob(glob) )
        result.second.push_back(std::move(p));

    return result;
}

std::vector<std::vector<Value>> FilesListPosix::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    auto [pattern, paths] = expandPaths(args);

    for ( const auto& p : paths ) {
        Value path = p.string();
        Value type;
        Value uid;
        Value gid;
        Value mode;
        Value mtime;
        Value size;

        struct ::stat stat;
        if ( ::stat(p.string().c_str(), &stat) == 0 ) {
            uid = static_cast<int64_t>(stat.st_uid);
            gid = static_cast<int64_t>(stat.st_gid);
            mode = frmt("{:o}", (stat.st_mode & ~S_IFMT));
            mtime = to_time(stat.st_mtime);
            size = stat.st_size;

            if ( S_ISBLK(stat.st_mode) )
                type = "block";
            else if ( S_ISCHR(stat.st_mode) )
                type = "char";
            else if ( S_ISDIR(stat.st_mode) )
                type = "dir";
            else if ( S_ISFIFO(stat.st_mode) )
                type = "fifo";
            else if ( S_ISREG(stat.st_mode) )
                type = "file";
            else if ( S_ISSOCK(stat.st_mode) )
                type = "socket";
            else
                type = "other";
        }

        rows.push_back({pattern, path, type, uid, gid, mode, mtime, size});
    }

    return rows;
}

std::vector<std::vector<Value>> FilesLinesPosix::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    auto [pattern, paths] = expandPaths(args);

    for ( const auto& p : paths ) {
        std::ifstream in(p);
        if ( in.fail() ) {
            // If file simply doesn't exist, we silently ignore the error.
            // Otherwise we add one row with `line` unset as an error indicator.
            if ( filesystem::exists(p) )
                rows.push_back({p, {}, "<failed to open file>"});

            continue;
        }

        int64_t number = 0;
        std::string content;

        // TODO: should use a version of getline() that can abort at a given max-size.
        while ( std::getline(in, content) )
            rows.push_back({pattern, p.native(), ++number, trim(content)});

        in.close();
    }

    return rows;
}

std::vector<std::vector<Value>> FilesColumnsPosix::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    // TODO: We don't have a way currently to preprocess column-spec and
    // ignore-expression ahead of time, so need to recompile it every time. The
    // problem is that there's not way to attach state to the current query.
    // Not sure how to do that, but in practice it probably doesn't matter much
    // anyways.

    auto separator = Table::getArgument<std::string>(args, "_separator");
    auto [pattern, paths] = expandPaths(args);

    auto spec = Table::getArgument<std::string>(args, "_columns");
    auto columns = parseColumnsSpec(spec);
    if ( ! columns )
        throw table::PermanentContentError(frmt("invalid column specification for 'files_columns': {}", spec));

    auto ignore = Table::getArgument<std::string>(args, "_ignore");
    std::optional<regex_t> ignore_regex;

    if ( ! ignore.empty() ) {
        ignore_regex = regex_t();
        if ( auto rc = regcomp(&*ignore_regex, ignore.c_str(), REG_EXTENDED | REG_NOSUB) )
            throw table::PermanentContentError(frmt("invalid ignore regex for 'files_columns': {}", ignore));
    }

    ScopeGuard _([&ignore_regex] {
        if ( ignore_regex )
            regfree(&*ignore_regex);
    });

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
            if ( ignore_regex && regexec(&*ignore_regex, line.data(), line.size(), nullptr, 0) == 0 )
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

            rows.push_back({pattern, spec, separator, ignore, p.native(), ++number, std::move(value)});
        }

        in.close();
    }

    return rows;
}

} // namespace zeek::agent::table

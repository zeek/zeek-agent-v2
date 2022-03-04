// Copyright (c) 2021 by t:he Zeek Project. See LICENSE for details.

#include "files.h"

#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/platform.h"

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

namespace {
database::RegisterTable<FilesListPosix> _1;
database::RegisterTable<FilesLinesPosix> _2;
} // namespace

std::pair<std::string, std::vector<filesystem::path>> FilesBase::expandPaths(const std::vector<table::Argument>& args) {
    std::pair<std::string, std::vector<filesystem::path>> result;

    for ( const auto& a : args ) {
        if ( a.column == "_pattern" ) {
            auto glob = std::get<std::string>(a.expression);
            result.first = glob;
            for ( auto p : platform::glob(glob) )
                result.second.push_back(std::move(p));
        }
    }

    return result;
}

std::vector<std::vector<Value>> FilesListPosix::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    auto [pattern, paths] = expandPaths(args);

    for ( const auto& p : paths ) {
        Value path = p;
        Value type;
        Value uid;
        Value gid;
        Value mode;
        Value mtime;
        Value size;

        struct ::stat stat;
        if ( ::stat(p.native().c_str(), &stat) == 0 ) {
            uid = static_cast<int64_t>(stat.st_uid);
            gid = static_cast<int64_t>(stat.st_gid);
            mode = format("{:o}", (stat.st_mode & ~S_IFMT));
            mtime = stat.st_mtime;
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
        // TODO: We should use a version of getline() that can abort at a given max-size.
        while ( std::getline(in, content) )
            rows.push_back({pattern, p.native(), ++number, trim(content)});

        in.close();
    }

    return rows;
}

} // namespace zeek::agent::table

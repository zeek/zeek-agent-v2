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
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override;
};

class FilesLinesPosix : public FilesLinesCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override;
};

namespace {
database::RegisterTable<FilesListPosix> _1;
database::RegisterTable<FilesLinesPosix> _2;
} // namespace

std::vector<filesystem::path> FilesBase::expandPaths(const std::vector<table::Where>& wheres) {
    std::vector<filesystem::path> paths;
    std::vector<filesystem::path> patterns;

    for ( const auto& where : wheres ) {
        if ( where.column == "path" && where.op == table::Operator::Equal )
            paths.push_back(std::get<std::string>(where.expression));

        if ( where.column == "path" && where.op == table::Operator::Glob )
            patterns.push_back(std::get<std::string>(where.expression));

        // TODO: we can't enforce use of specific operators currently, so if
        // somebody uses, e.g., LIKE, we'll end up without a pattern.
    }

    for ( auto p : platform::glob(patterns) )
        paths.push_back(std::move(p));

    return paths;
}

std::vector<std::vector<Value>> FilesListPosix::snapshot(const std::vector<table::Where>& wheres) {
    std::vector<std::vector<Value>> rows;

    for ( auto p : expandPaths(wheres) ) {
        Value path = p;
        Value type, uid, gid, mode, mtime, size;

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

        rows.push_back({path, type, uid, gid, mode, mtime, size});
    }

    return rows;
}

std::vector<std::vector<Value>> FilesLinesPosix::snapshot(const std::vector<table::Where>& wheres) {
    std::vector<std::vector<Value>> rows;

    for ( auto p : expandPaths(wheres) ) {
        std::ifstream in(p);
        if ( in.fail() ) {
            // As an error indicator, we add one row with `line` unset.
            rows.push_back({p, {}, "<failed to open file>"});
            continue;
        }

        int64_t line = 0;
        std::string data;
        // TODO: We should use a version of geline() that can abort at a given max-size.
        while ( std::getline(in, data) )
            rows.push_back({p, ++line, trim(data)});

        in.close();
    }

    return rows;
}

} // namespace zeek::agent::table

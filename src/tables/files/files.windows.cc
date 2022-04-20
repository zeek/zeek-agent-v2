// Copyright (c) 2021 by t:he Zeek Project. See LICENSE for details.

#include "files.h"

#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/platform.h"
#include "util/platform.windows.h"

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

static std::string get_full_path(const std::string& pattern, const char* filename) {
    char ret[MAX_PATH];
    char* tmp = new char[pattern.size() + 1];
    strncpy(tmp, pattern.c_str(), pattern.size());
    tmp[pattern.size()] = '\0';

    PathRemoveFileSpecA(tmp);
    PathCombineA(ret, tmp, filename);
    delete[] tmp;
    return ret;
}

std::pair<std::string, std::vector<filesystem::path>> FilesBase::expandPaths(const std::vector<table::Argument>& args) {
    logger()->warn("FilesBase::expandPaths is not implemented on Windows");
    return {};
}

std::vector<Value> FilesListWindows::buildFileRow(const std::string& pattern, const WIN32_FIND_DATAA& data) const {
    std::vector<Value> row;
    std::string full_path = get_full_path(pattern, data.cFileName);

    Value path = full_path;
    Value type;

    uint16_t temp_mode = 0;
    if ( data.dwFileAttributes & FILE_ATTRIBUTE_READONLY )
        temp_mode = 0444;
    else
        temp_mode = 0666;

    if ( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {
        // TODO: not sure this addition to the mode is correct
        temp_mode += 0111;
        type = "dir";
    }
    else {
        // The data from FindFirstFile doesn't include a file type and the handle that's
        // returned isn't a file handle (it's a search handle). Open the file separately
        // and call GetFileType(), and then close it again.
        DWORD file_type = FILE_TYPE_UNKNOWN;
        HandlePtr file_handle{CreateFileA(full_path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL)};

        if ( file_handle.get() == INVALID_HANDLE_VALUE ) {
            std::error_condition cond =
                std::system_category().default_error_condition(static_cast<int>(GetLastError()));
            logger()->warn(
                format("Couldn't open file {} to check for type: {} ({})", full_path, cond.message(), cond.value()));
        }
        else {
            file_type = GetFileType(file_handle.get());
        }

        // A few fields here don't match the counterparts on Linux. Added is 'remote',
        // and missing is 'block' and 'socket'.
        switch ( file_type ) {
            case FILE_TYPE_CHAR: type = "char"; break;
            // FILE_TYPE_DISK is just your average everyday file on a drive.
            case FILE_TYPE_DISK: type = "file"; break;
            // fifo on Linux is roughly the same thing as a Windows pipe.
            case FILE_TYPE_PIPE: type = "fifo"; break;
            // FILE_TYPE_REMOTE is marked as unused in the documentation.
            case FILE_TYPE_REMOTE: type = "remote"; break;
            case FILE_TYPE_UNKNOWN:
            default: type = "other"; break;
        }
    }

    Value mode = format("{:o}", temp_mode);
    Value size = combineHighLow(data.nFileSizeHigh, data.nFileSizeLow);
    Value mtime = to_time(convertFiletime(data.ftLastWriteTime));

    return {pattern, path, type, {}, {}, mode, mtime, size};
}

std::vector<std::vector<Value>> FilesListWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    for ( const auto& a : args ) {
        if ( a.column == "_pattern" ) {
            auto& pattern = std::get<std::string>(a.expression);

            // TODO: how much of the linux file-globbing pattern API do we actually
            // support here? Windows definitely doesn't support the whole gamut,
            // like **.

            WIN32_FIND_DATAA find_data{};
            FindHandlePtr handle{FindFirstFileA(pattern.c_str(), &find_data)};
            if ( handle.get() == INVALID_HANDLE_VALUE )
                continue;

            int find_ret = NO_ERROR;
            do {
                // Ignore the . and .. directories returned by FindFirstFile
                if ( strcmp(find_data.cFileName, ".") != 0 && strcmp(find_data.cFileName, "..") != 0 )
                    rows.emplace_back(buildFileRow(pattern, find_data));

                find_ret = FindNextFile(handle.get(), &find_data);

            } while ( find_ret != 0 );

            if ( GetLastError() != ERROR_NO_MORE_FILES ) {
                std::error_condition cond =
                    std::system_category().default_error_condition(static_cast<int>(GetLastError()));
                logger()->warn(format("Failed to find next file: {} ({})", cond.message(), cond.value()));
            }
        }
    }

    return rows;
}

std::vector<std::vector<Value>> FilesLinesWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    for ( const auto& a : args ) {
        if ( a.column == "_pattern" ) {
            auto& pattern = std::get<std::string>(a.expression);

            // TODO: how much of the linux file-globbing pattern API do we actually
            // support here? Windows definitely doesn't support the whole gamut,
            // like **. I could support recursion, but it doesn't at the moment.

            WIN32_FIND_DATAA find_data{};
            FindHandlePtr handle{FindFirstFileA(pattern.c_str(), &find_data)};
            if ( handle.get() == INVALID_HANDLE_VALUE )
                continue;

            int find_ret = NO_ERROR;
            do {
                if ( (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ) {
                    std::string full_path = get_full_path(pattern, find_data.cFileName);
                    std::ifstream in(full_path);
                    if ( in.fail() ) {
                        // If file simply doesn't exist, we silently ignore the error.
                        // Otherwise we add one row with `line` unset as an error indicator.
                        if ( filesystem::exists(find_data.cFileName) )
                            rows.push_back({find_data.cFileName, {}, "<failed to open file>"});

                        continue;
                    }

                    int64_t number = 0;
                    std::string content;
                    // TODO: We should use a version of getline() that can abort at a given max-size.
                    while ( std::getline(in, content) )
                        rows.push_back({pattern, find_data.cFileName, ++number, trim(content)});

                    in.close();
                }

                find_ret = FindNextFile(handle.get(), &find_data);

            } while ( find_ret != 0 );

            if ( GetLastError() != ERROR_NO_MORE_FILES ) {
                std::error_condition cond =
                    std::system_category().default_error_condition(static_cast<int>(GetLastError()));
                logger()->warn(format("Failed to find next file: {} ({})", cond.message(), cond.value()));
            }
        }
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
        throw table::PermanentContentError(format("invalid column specification for 'files_columns': {}", spec));

    auto& ignore = Table::getArgument<std::string>(args, "_ignore");
    std::optional<std::regex> ignore_regex;

    if ( ! ignore.empty() ) {
        try {
            ignore_regex = std::regex{ignore, std::regex::extended | std::regex::nosubs};
        } catch ( const std::regex_error& err ) {
            throw table::PermanentContentError(format("invalid ignore regex for 'files_columns': {}", ignore));
        }
    }

    for ( const auto& a : args ) {
        if ( a.column == "_pattern" ) {
            auto& pattern = std::get<std::string>(a.expression);

            // TODO: how much of the linux file-globbing pattern API do we actually
            // support here? Windows definitely doesn't support the whole gamut,
            // like **. I could support recursion, but it doesn't at the moment.

            WIN32_FIND_DATAA find_data{};
            FindHandlePtr handle{FindFirstFileA(pattern.c_str(), &find_data)};
            if ( handle.get() == INVALID_HANDLE_VALUE )
                continue;

            int find_ret = NO_ERROR;
            do {
                if ( (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ) {
                    std::string full_path = get_full_path(pattern, find_data.cFileName);
                    std::ifstream in(full_path);
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

                        rows.push_back({pattern, spec, separator, ignore, full_path, ++number, std::move(value)});
                    }

                    in.close();
                }

                find_ret = FindNextFile(handle.get(), &find_data);

            } while ( find_ret != 0 );

            if ( GetLastError() != ERROR_NO_MORE_FILES ) {
                std::error_condition cond =
                    std::system_category().default_error_condition(static_cast<int>(GetLastError()));
                logger()->warn(format("Failed to find next file: {} ({})", cond.message(), cond.value()));
            }
        }
    }

    return rows;
}

} // namespace zeek::agent::table

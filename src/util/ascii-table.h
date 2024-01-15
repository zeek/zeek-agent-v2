// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include <ostream>
#include <string>
#include <utility>
#include <vector>

namespace zeek::agent {

/** Helper class to pretty-print a table of values. */
class AsciiTable {
public:
    /** Adds a header row to the table. */
    void addHeader(std::vector<std::string> row);

    /** Adds a data row to the table. */
    void addRow(std::vector<std::string> row);

    /** Render the rows added so far to an output stream. */
    void print(std::ostream& out, bool include_header = true);

    /**
     * Clears out any rows added so far.
     *
     * @param reset_column_withds if falls, keep state on the maximum column
     * width so far, meaning subsequently added rows will print as if a row was
     * still having that width
     */
    void clear(bool reset_colum_widths = true);

private:
    void printRow(std::ostream& out, const std::vector<std::string>& row, bool is_header, bool is_border,
                  const char* sep);

    std::vector<std::pair<bool, std::vector<std::string>>> _rows;
    std::vector<std::string::size_type> _column_widths;
};

} // namespace zeek::agent

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "ascii-table.h"

#include "util/color.h"
#include "util/helpers.h"

#include <algorithm>
#include <iomanip>
#include <iostream>

using namespace zeek::agent;

void AsciiTable::addHeader(std::vector<std::string> row) {
    addRow(std::move(row));
    _rows.back().first = true;
}

void AsciiTable::addRow(std::vector<std::string> row) {
    if ( _column_widths.size() < row.size() )
        _column_widths.resize(row.size());

    for ( auto i = 0U; i < _column_widths.size(); i++ )
        _column_widths[i] = std::max(row[i].size(), _column_widths[i]);

    _rows.emplace_back(false, std::move(row));
}

void AsciiTable::clear(bool reset_colum_widths) {
    _rows.clear();

    if ( reset_colum_widths )
        _column_widths.clear();
}

void AsciiTable::printRow(std::ostream& out, const std::vector<std::string>& row, bool is_header, bool is_border,
                          const char* sep) {
    for ( auto i = 0U; i < _column_widths.size(); i++ ) {
        auto width = _column_widths[i];
        auto value = (i < row.size() ? row[i] : std::string());
        auto fill_left = std::string((width - value.size()) / 2, ' ');
        auto fill_right = std::string(width - fill_left.size() - value.size(), ' ');

        if ( is_header )
            value = color::yellow(value);
        else if ( is_border )
            value = color::normal(value);

        if ( i > 0 )
            out << sep;

        out << fill_left << value << fill_right;
    }

    out << '\n' << std::flush;
}

void AsciiTable::print(std::ostream& out, bool include_header) {
    auto border = transform(_column_widths, [](auto i) { return std::string(i, '-'); });

    for ( const auto& r : _rows ) {
        if ( r.first && ! include_header )
            continue;

        printRow(out, r.second, r.first, false, "  ");

        if ( r.first )
            printRow(out, border, false, true, "  ");
    }
}

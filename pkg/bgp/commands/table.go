// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"encoding/json"
	"fmt"
	"io"
)

type tableJSON struct {
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
}

func writeJSON(w io.Writer, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal failed: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return err
	}
	return nil
}

func writeTableJSON(w io.Writer, columns []string, rows [][]string) error {
	tableRows := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		tableRow := make(map[string]string, len(columns))
		for i, column := range columns {
			if i < len(row) {
				tableRow[column] = row[i]
			} else {
				tableRow[column] = ""
			}
		}
		tableRows = append(tableRows, tableRow)
	}
	return writeJSON(w, tableJSON{
		Columns: columns,
		Rows:    tableRows,
	})
}

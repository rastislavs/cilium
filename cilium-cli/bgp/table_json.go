// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"encoding/json"
	"strings"
)

type tableJSON struct {
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
}

func tableJSONRowsToStrings(data []byte) ([]string, error) {
	var table tableJSON
	if err := json.Unmarshal(data, &table); err != nil {
		return nil, err
	}

	out := []string{strings.Join(table.Columns, "\t")}
	for i, row := range table.Rows {
		fields := make([]string, 0, len(table.Columns))
		for columnIndex, column := range table.Columns {
			value := row[column]
			if i > 0 && hasSamePrefix(table.Columns[:columnIndex+1], table.Rows[i-1], row) {
				value = ""
			}
			fields = append(fields, value)
		}
		out = append(out, strings.Join(fields, "\t"))
	}
	return out, nil
}

func hasSamePrefix(columns []string, previous, current map[string]string) bool {
	for _, column := range columns {
		if previous[column] != current[column] {
			return false
		}
	}
	return true
}

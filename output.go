package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// OutputResults は検証結果をJSON形式で出力する
func OutputResults(results []LintResult, stdout io.Writer) error {
	if len(results) == 0 {
		return nil
	}

	// JSON形式で出力
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("JSON変換に失敗しました: %w", err)
	}
	return fmt.Errorf("RLS設定の不足があります")
}

// SetFilename は検証結果のファイル名を設定する
func SetFilename(results []LintResult, filename string) {
	for i := range results {
		results[i].Location.File = filename
	}
}

package main

import (
	"flag"
	"os"
	"strings"
)

// ParseFlags はコマンドラインフラグを解析する
func ParseFlags() (excludedTables []string, useStdin bool) {
	var excludedTablesStr string
	flag.StringVar(&excludedTablesStr, "exclude", "", "Tables to exclude from RLS validation (comma-separated)")
	flag.BoolVar(&useStdin, "stdin", false, "Read SQL from standard input")
	flag.Parse()

	// 除外テーブルのリスト作成
	if excludedTablesStr != "" {
		excludedTables = strings.Split(excludedTablesStr, ",")
	}

	return excludedTables, useStdin
}

// ProcessStdin は標準入力からSQLを読み込んで検証する
func ProcessStdin(excludedTables []string) error {
	options := LinterOptions{
		Sources: []SourceFile{
			{
				Reader:   os.Stdin,
				Filename: "stdin",
			},
		},
		Writer:         os.Stdout,
		ExcludedTables: excludedTables,
	}

	return RunLinter(options)
}

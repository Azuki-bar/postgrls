package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	// コマンドライン引数の解析
	excludedTables, useStdin := ParseFlags()

	var sources []SourceFile

	// 標準入力からの読み込み
	if useStdin {
		sources = []SourceFile{
			{
				Reader:   os.Stdin,
				Filename: "stdin",
			},
		}
	} else {
		// ファイル引数がない場合はヘルプを表示
		if flag.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Usage: postgrls [options] file...")
			flag.PrintDefaults()
			os.Exit(1)
		}

		// ファイル名のリストからSourceFileの配列を作成
		sources = make([]SourceFile, 0, len(flag.Args()))
		for _, filename := range flag.Args() {
			file, err := os.Open(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not open file: %s: %v\n", filename, err)
				os.Exit(1)
			}
			defer file.Close()

			sources = append(sources, SourceFile{
				Reader:   file,
				Filename: filename,
			})
		}
	}

	// リンターの実行
	options := LinterOptions{
		Sources:        sources,
		Writer:         os.Stdout,
		ExcludedTables: excludedTables,
	}

	if err := RunLinter(options); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// RunLinter はソースに対してリンターを実行する
func RunLinter(options LinterOptions) error {
	// 入力ソースが空の場合はエラー
	if len(options.Sources) == 0 {
		return fmt.Errorf("no input sources specified")
	}

	// すべてのソースからテーブル定義、RLS有効化、ポリシーを収集
	var allTables []TableDefinition
	var allRLSEnables []RLSEnableStatement
	var allPolicies []PolicyStatement

	for _, source := range options.Sources {
		// SQLの読み込み
		sqlBytes, err := io.ReadAll(source.Reader)
		if err != nil {
			return fmt.Errorf("failed to read SQL: %s: %w", source.Filename, err)
		}

		// SQLの解析
		tables, rlsEnables, policies, err := ParseSQL(source.Filename, string(sqlBytes))
		if err != nil {
			return fmt.Errorf("failed to parse SQL: %s: %w", source.Filename, err)
		}

		// 結果を統合
		allTables = append(allTables, tables...)
		allRLSEnables = append(allRLSEnables, rlsEnables...)
		allPolicies = append(allPolicies, policies...)
	}

	// RLS設定の検証
	results := ValidateRLS(allTables, allRLSEnables, allPolicies, options.ExcludedTables)

	// 結果の出力
	return OutputResults(results, options.Writer)
}

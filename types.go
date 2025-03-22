package main

import (
	"io"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// SourceFile はリンター入力のソースファイルを表す構造体
type SourceFile struct {
	Reader   io.Reader // 入力ソース
	Filename string    // ファイル名
}

// LinterOptions はリンターのオプションを表す構造体
type LinterOptions struct {
	Sources        []SourceFile // 入力ソース（複数可）
	Writer         io.Writer    // 出力先
	ExcludedTables []string     // 除外テーブル
}

// LintResult は検証結果を表す構造体
type LintResult struct {
	Message  string `json:"message"`
	Location struct {
		File   string `json:"file"`
		Line   int    `json:"line"`
		Column int    `json:"column"`
	} `json:"location"`
	TableName string `json:"table_name"`
	RuleID    string `json:"rule_id"`
}

// SQLStatement はSQLステートメントの基本情報を表す構造体
type SQLStatement struct {
	Filename string
	Line     int
	Column   int
}

// TableDefinition はテーブル定義を表す構造体
type TableDefinition struct {
	SQLStatement
	TableName string
	Statement *pg_query.CreateStmt
}

// RLSEnableStatement はRLS有効化文を表す構造体
type RLSEnableStatement struct {
	SQLStatement
	TableName string
	Statement *pg_query.AlterTableStmt
}

// PolicyStatement はポリシー定義を表す構造体
type PolicyStatement struct {
	SQLStatement
	TableName  string
	PolicyName string
	Statement  *pg_query.CreatePolicyStmt
}

// TableInfo はテーブルに関する情報を統合した構造体
type TableInfo struct {
	TableName  string
	Definition *TableDefinition
	EnableRLS  *RLSEnableStatement
	Policies   []*PolicyStatement
}

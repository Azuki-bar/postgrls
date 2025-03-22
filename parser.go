package main

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// ParseSQL はSQLを解析してステートメントを抽出する
func ParseSQL(filename string, sql string) ([]TableDefinition, []RLSEnableStatement, []PolicyStatement, error) {
	// SQLの解析
	tree, err := pg_query.Parse(sql)
	if err != nil {
		return nil, nil, nil, err
	}

	// 各種ステートメントの抽出
	tables := extractTableDefinitions(filename, tree)
	rlsEnables := extractRLSEnableStatements(filename, tree)
	policies := extractPolicyStatements(filename, tree)

	return tables, rlsEnables, policies, nil
}

// extractTableDefinitions はCREATE TABLE文を抽出する
func extractTableDefinitions(filename string, tree *pg_query.ParseResult) []TableDefinition {
	tables := make([]TableDefinition, 0)

	for _, stmt := range tree.Stmts {
		if res := stmt.Stmt.GetCreateStmt(); res != nil {
			tableName := res.GetRelation().GetRelname()

			// 位置情報の取得
			location := SQLStatement{
				Filename: filename,
				Line:     int(stmt.StmtLocation), // 実際の位置情報を使用
				Column:   1,
			}

			tables = append(tables, TableDefinition{
				SQLStatement: location,
				TableName:    tableName,
				Statement:    res,
			})
		}
	}

	return tables
}

// extractRLSEnableStatements はALTER TABLE ... ENABLE ROW LEVEL SECURITY文を抽出する
func extractRLSEnableStatements(filename string, tree *pg_query.ParseResult) []RLSEnableStatement {
	rlsEnables := make([]RLSEnableStatement, 0)

	for _, stmt := range tree.Stmts {
		if res := stmt.Stmt.GetAlterTableStmt(); res != nil {
			tableName := res.GetRelation().GetRelname()

			// RLS有効化のステートメントかチェック
			isRLSEnable := false
			for _, cmd := range res.Cmds {
				if cmd.GetAlterTableCmd() != nil {
					subtype := cmd.GetAlterTableCmd().Subtype
					if subtype == pg_query.AlterTableType_AT_EnableRowSecurity {
						isRLSEnable = true
						break
					}
				}
			}

			if isRLSEnable {
				// 位置情報の取得
				location := SQLStatement{
					Filename: filename,
					Line:     int(stmt.StmtLocation),
					Column:   1,
				}

				rlsEnables = append(rlsEnables, RLSEnableStatement{
					SQLStatement: location,
					TableName:    tableName,
					Statement:    res,
				})
			}
		}
	}

	return rlsEnables
}

// extractPolicyStatements はCREATE POLICY文を抽出する
func extractPolicyStatements(filename string, tree *pg_query.ParseResult) []PolicyStatement {
	policies := make([]PolicyStatement, 0)

	for _, stmt := range tree.Stmts {
		if res := stmt.Stmt.GetCreatePolicyStmt(); res != nil {
			tableName := res.GetTable().GetRelname()
			policyName := res.GetPolicyName()

			// 位置情報の取得
			location := SQLStatement{
				Filename: filename,
				Line:     int(stmt.StmtLocation),
				Column:   1,
			}

			policies = append(policies, PolicyStatement{
				SQLStatement: location,
				TableName:    tableName,
				PolicyName:   policyName,
				Statement:    res,
			})
		}
	}

	return policies
}

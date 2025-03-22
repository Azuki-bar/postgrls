package main

// ValidateRLS はテーブル定義に対してRLS設定の検証を行う
func ValidateRLS(tables []TableDefinition, rlsEnables []RLSEnableStatement, policies []PolicyStatement, excludedTables []string) []LintResult {
	// テーブル情報の統合
	tableInfoMap := make(map[string]*TableInfo)

	// テーブル定義の登録
	for _, table := range tables {
		if !isExcluded(table.TableName, excludedTables) {
			tableInfoMap[table.TableName] = &TableInfo{
				TableName:  table.TableName,
				Definition: &table,
			}
		}
	}

	// RLS有効化の登録
	for _, rlsEnable := range rlsEnables {
		if info, exists := tableInfoMap[rlsEnable.TableName]; exists {
			info.EnableRLS = &rlsEnable
		}
	}

	// ポリシーの登録
	for _, policy := range policies {
		if info, exists := tableInfoMap[policy.TableName]; exists {
			info.Policies = append(info.Policies, &policy)
		}
	}

	// 検証結果の作成
	results := make([]LintResult, 0)

	for _, info := range tableInfoMap {
		// RLSが有効化されていない場合
		if info.EnableRLS == nil {
			results = append(results, LintResult{
				Message:   "テーブル '" + info.TableName + "' にRLSが有効化されていません",
				TableName: info.TableName,
				RuleID:    "rls-not-enabled",
				Location: struct {
					File   string `json:"file"`
					Line   int    `json:"line"`
					Column int    `json:"column"`
				}{
					File:   info.Definition.Filename,
					Line:   info.Definition.Line,
					Column: info.Definition.Column,
				},
			})
		} else if len(info.Policies) == 0 {
			// RLSは有効だがポリシーが設定されていない場合
			results = append(results, LintResult{
				Message:   "テーブル '" + info.TableName + "' にRLSポリシーが設定されていません",
				TableName: info.TableName,
				RuleID:    "rls-no-policy",
				Location: struct {
					File   string `json:"file"`
					Line   int    `json:"line"`
					Column int    `json:"column"`
				}{
					File:   info.Definition.Filename,
					Line:   info.Definition.Line,
					Column: info.Definition.Column,
				},
			})
		}
	}

	return results
}

// isExcluded は指定されたテーブルが除外リストに含まれているかを確認する
func isExcluded(tableName string, excludedTables []string) bool {
	for _, excluded := range excludedTables {
		if tableName == excluded {
			return true
		}
	}
	return false
}

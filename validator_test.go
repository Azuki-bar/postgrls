package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRLS_NoTables(t *testing.T) {
	// テーブルがない場合
	result := ValidateRLS([]TableDefinition{}, []RLSEnableStatement{}, []PolicyStatement{}, []string{})
	assert.Empty(t, result)
}

func TestValidateRLS_MissingRLSEnable(t *testing.T) {
	// テーブル定義のみで、RLS有効化がない場合
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	result := ValidateRLS(tables, []RLSEnableStatement{}, []PolicyStatement{}, []string{})

	assert.Len(t, result, 1)
	assert.Equal(t, "accounts", result[0].TableName)
	assert.Equal(t, "rls-not-enabled", result[0].RuleID)
	assert.Contains(t, result[0].Message, "RLSが有効化されていません")
}

func TestValidateRLS_MissingPolicy(t *testing.T) {
	// テーブル定義とRLS有効化はあるが、ポリシーがない場合
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	result := ValidateRLS(tables, rlsEnables, []PolicyStatement{}, []string{})

	assert.Len(t, result, 1)
	assert.Equal(t, "accounts", result[0].TableName)
	assert.Equal(t, "rls-no-policy", result[0].RuleID)
	assert.Contains(t, result[0].Message, "RLSポリシーが設定されていません")
}

func TestValidateRLS_Complete(t *testing.T) {
	// テーブル定義、RLS有効化、ポリシーがすべて揃っている場合
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	policies := []PolicyStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     3,
				Column:   1,
			},
			TableName:  "accounts",
			PolicyName: "account_policy",
		},
	}

	result := ValidateRLS(tables, rlsEnables, policies, []string{})

	assert.Empty(t, result)
}

func TestValidateRLS_ExcludedTable(t *testing.T) {
	// 除外リストに含まれるテーブルの場合
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	result := ValidateRLS(tables, []RLSEnableStatement{}, []PolicyStatement{}, []string{"accounts"})

	assert.Empty(t, result)
}

func TestValidateRLS_MultipleTables(t *testing.T) {
	// 複数のテーブルがある場合
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     5,
				Column:   1,
			},
			TableName: "users",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	policies := []PolicyStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     3,
				Column:   1,
			},
			TableName:  "accounts",
			PolicyName: "account_policy",
		},
	}

	result := ValidateRLS(tables, rlsEnables, policies, []string{})

	assert.Len(t, result, 1)
	assert.Equal(t, "users", result[0].TableName)
	assert.Equal(t, "rls-not-enabled", result[0].RuleID)
}

func TestValidateRLS_MultiplePolicies(t *testing.T) {
	// 1つのテーブルに複数のポリシーがある場合
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	policies := []PolicyStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     3,
				Column:   1,
			},
			TableName:  "accounts",
			PolicyName: "policy1",
		},
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     4,
				Column:   1,
			},
			TableName:  "accounts",
			PolicyName: "policy2",
		},
	}

	result := ValidateRLS(tables, rlsEnables, policies, []string{})

	assert.Empty(t, result)
}

func TestValidateRLS_LocationInfo(t *testing.T) {
	// 位置情報が正しく設定されるかテスト
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     10,
				Column:   5,
			},
			TableName: "accounts",
		},
	}

	result := ValidateRLS(tables, []RLSEnableStatement{}, []PolicyStatement{}, []string{})

	assert.Len(t, result, 1)
	assert.Equal(t, "test.sql", result[0].Location.File)
	assert.Equal(t, 10, result[0].Location.Line)
	assert.Equal(t, 5, result[0].Location.Column)
}

func TestIsExcluded(t *testing.T) {
	testCases := map[string]struct {
		tableName      string
		excludedTables []string
		expected       bool
	}{
		"empty exclude list": {
			tableName:      "accounts",
			excludedTables: []string{},
			expected:       false,
		},
		"table in exclude list": {
			tableName:      "accounts",
			excludedTables: []string{"users", "accounts", "products"},
			expected:       true,
		},
		"table not in exclude list": {
			tableName:      "accounts",
			excludedTables: []string{"users", "products"},
			expected:       false,
		},
		"case sensitive": {
			tableName:      "Accounts",
			excludedTables: []string{"accounts"},
			expected:       false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := isExcluded(tc.tableName, tc.excludedTables)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateRLS_WithFixtures(t *testing.T) {
	// testdata/fixtures/test.sqlの内容を元にしたテスト
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "users",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     3,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	policies := []PolicyStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     4,
				Column:   1,
			},
			TableName:  "accounts",
			PolicyName: "account_managers",
		},
	}

	result := ValidateRLS(tables, rlsEnables, policies, []string{})

	assert.Len(t, result, 1)
	assert.Equal(t, "users", result[0].TableName)
	assert.Equal(t, "rls-not-enabled", result[0].RuleID)
}

func TestValidateRLS_WithFixtures2(t *testing.T) {
	// testdata/fixtures/test2.sqlの内容を元にしたテスト
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test2.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "products",
		},
		{
			SQLStatement: SQLStatement{
				Filename: "test2.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "orders",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test2.sql",
				Line:     3,
				Column:   1,
			},
			TableName: "products",
		},
	}

	policies := []PolicyStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test2.sql",
				Line:     4,
				Column:   1,
			},
			TableName:  "products",
			PolicyName: "product_policy",
		},
	}

	result := ValidateRLS(tables, rlsEnables, policies, []string{})

	assert.Len(t, result, 1)
	assert.Equal(t, "orders", result[0].TableName)
	assert.Equal(t, "rls-not-enabled", result[0].RuleID)
}

func TestValidateRLS_WithExcludedTables(t *testing.T) {
	// 除外テーブルを指定したテスト
	tables := []TableDefinition{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     1,
				Column:   1,
			},
			TableName: "accounts",
		},
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     2,
				Column:   1,
			},
			TableName: "users",
		},
	}

	rlsEnables := []RLSEnableStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     3,
				Column:   1,
			},
			TableName: "accounts",
		},
	}

	policies := []PolicyStatement{
		{
			SQLStatement: SQLStatement{
				Filename: "test.sql",
				Line:     4,
				Column:   1,
			},
			TableName:  "accounts",
			PolicyName: "account_managers",
		},
	}

	// usersテーブルを除外
	result := ValidateRLS(tables, rlsEnables, policies, []string{"users"})

	assert.Empty(t, result)
}

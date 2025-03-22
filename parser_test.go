package main

import (
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"github.com/stretchr/testify/assert"
)

func TestParseSQL_Empty(t *testing.T) {
	// 空のSQLをテスト
	tables, rlsEnables, policies, err := ParseSQL("test.sql", "")

	assert.NoError(t, err)
	assert.Empty(t, tables)
	assert.Empty(t, rlsEnables)
	assert.Empty(t, policies)
}

func TestParseSQL_InvalidSQL(t *testing.T) {
	// 無効なSQLをテスト
	_, _, _, err := ParseSQL("test.sql", "CREATE TABL accounts;")

	assert.Error(t, err)
}

func TestParseSQL_CompleteSQL(t *testing.T) {
	// 完全なSQLをテスト
	sql := `
	CREATE TABLE accounts (id int, manager text);
	CREATE TABLE users (id int, name text);
	ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
	CREATE POLICY account_managers ON accounts USING (manager = current_user);
	`

	tables, rlsEnables, policies, err := ParseSQL("test.sql", sql)

	assert.NoError(t, err)
	assert.Len(t, tables, 2)
	assert.Len(t, rlsEnables, 1)
	assert.Len(t, policies, 1)

	// テーブル名の検証
	tableNames := []string{}
	for _, table := range tables {
		tableNames = append(tableNames, table.TableName)
	}
	assert.Contains(t, tableNames, "accounts")
	assert.Contains(t, tableNames, "users")

	// RLS有効化の検証
	assert.Equal(t, "accounts", rlsEnables[0].TableName)

	// ポリシーの検証
	assert.Equal(t, "accounts", policies[0].TableName)
	assert.Equal(t, "account_managers", policies[0].PolicyName)
}

func TestExtractTableDefinitions(t *testing.T) {
	testCases := map[string]struct {
		sql           string
		expectedCount int
		expectedNames []string
	}{
		"empty": {
			sql:           "",
			expectedCount: 0,
			expectedNames: []string{},
		},
		"single table": {
			sql:           "CREATE TABLE accounts (id int);",
			expectedCount: 1,
			expectedNames: []string{"accounts"},
		},
		"multiple tables": {
			sql:           "CREATE TABLE accounts (id int); CREATE TABLE users (id int);",
			expectedCount: 2,
			expectedNames: []string{"accounts", "users"},
		},
		"quoted table name": {
			sql:           `CREATE TABLE "user accounts" (id int);`,
			expectedCount: 1,
			expectedNames: []string{"user accounts"},
		},
		"with schema": {
			sql:           `CREATE TABLE public.accounts (id int);`,
			expectedCount: 1,
			expectedNames: []string{"accounts"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// SQLをパース
			tree, err := pg_query.Parse(tc.sql)
			assert.NoError(t, err)

			// テーブル定義を抽出
			tables := extractTableDefinitions("test.sql", tree)

			// 検証
			assert.Len(t, tables, tc.expectedCount)

			// テーブル名の検証
			tableNames := []string{}
			for _, table := range tables {
				tableNames = append(tableNames, table.TableName)
			}

			for _, expectedName := range tc.expectedNames {
				assert.Contains(t, tableNames, expectedName)
			}
		})
	}
}

func TestExtractRLSEnableStatements(t *testing.T) {
	testCases := map[string]struct {
		sql           string
		expectedCount int
		expectedNames []string
	}{
		"empty": {
			sql:           "",
			expectedCount: 0,
			expectedNames: []string{},
		},
		"single enable": {
			sql:           "ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;",
			expectedCount: 1,
			expectedNames: []string{"accounts"},
		},
		"multiple enables": {
			sql:           "ALTER TABLE accounts ENABLE ROW LEVEL SECURITY; ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
			expectedCount: 2,
			expectedNames: []string{"accounts", "users"},
		},
		"with other alter commands": {
			sql:           "ALTER TABLE accounts ADD COLUMN email text; ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;",
			expectedCount: 1,
			expectedNames: []string{"accounts"},
		},
		"quoted table name": {
			sql:           `ALTER TABLE "user accounts" ENABLE ROW LEVEL SECURITY;`,
			expectedCount: 1,
			expectedNames: []string{"user accounts"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// SQLをパース
			tree, err := pg_query.Parse(tc.sql)
			assert.NoError(t, err)

			// RLS有効化文を抽出
			rlsEnables := extractRLSEnableStatements("test.sql", tree)

			// 検証
			assert.Len(t, rlsEnables, tc.expectedCount)

			// テーブル名の検証
			tableNames := []string{}
			for _, rlsEnable := range rlsEnables {
				tableNames = append(tableNames, rlsEnable.TableName)
			}

			for _, expectedName := range tc.expectedNames {
				assert.Contains(t, tableNames, expectedName)
			}
		})
	}
}

func TestExtractPolicyStatements(t *testing.T) {
	testCases := map[string]struct {
		sql               string
		expectedCount     int
		expectedTableName string
		expectedPolicies  []string
	}{
		"empty": {
			sql:               "",
			expectedCount:     0,
			expectedTableName: "",
			expectedPolicies:  []string{},
		},
		"single policy": {
			sql:               "CREATE POLICY account_managers ON accounts USING (manager = current_user);",
			expectedCount:     1,
			expectedTableName: "accounts",
			expectedPolicies:  []string{"account_managers"},
		},
		"multiple policies": {
			sql:               "CREATE POLICY policy1 ON accounts USING (true); CREATE POLICY policy2 ON accounts USING (false);",
			expectedCount:     2,
			expectedTableName: "accounts",
			expectedPolicies:  []string{"policy1", "policy2"},
		},
		"policies on different tables": {
			sql:               "CREATE POLICY policy1 ON accounts USING (true); CREATE POLICY policy2 ON users USING (true);",
			expectedCount:     2,
			expectedTableName: "",  // 複数のテーブルがあるので特定のテーブル名は期待しない
			expectedPolicies:  []string{"policy1", "policy2"},
		},
		"quoted policy name": {
			sql:               `CREATE POLICY "manager policy" ON accounts USING (manager = current_user);`,
			expectedCount:     1,
			expectedTableName: "accounts",
			expectedPolicies:  []string{"manager policy"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// SQLをパース
			tree, err := pg_query.Parse(tc.sql)
			assert.NoError(t, err)

			// ポリシー文を抽出
			policies := extractPolicyStatements("test.sql", tree)

			// 検証
			assert.Len(t, policies, tc.expectedCount)

			// ポリシー名の検証
			policyNames := []string{}
			for _, policy := range policies {
				policyNames = append(policyNames, policy.PolicyName)

				// 特定のテーブル名を期待する場合はそれも検証
				if tc.expectedTableName != "" {
					assert.Equal(t, tc.expectedTableName, policy.TableName)
				}
			}

			for _, expectedPolicy := range tc.expectedPolicies {
				assert.Contains(t, policyNames, expectedPolicy)
			}
		})
	}
}

func TestParseSQL_WithFixtures(t *testing.T) {
	// testdata/fixtures/test.sqlの内容をハードコード
	testSQL := `CREATE TABLE accounts (id int, manager text);
CREATE TABLE users (id int, name text);
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY account_managers ON accounts USING (manager = current_user);`

	// testdata/fixtures/test2.sqlの内容をハードコード
	test2SQL := `CREATE TABLE products (id int, name text, price int);
CREATE TABLE orders (id int, product_id int, quantity int);
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
CREATE POLICY product_policy ON products USING (true);`

	testCases := map[string]struct {
		sql                string
		expectedTables     int
		expectedRLSEnables int
		expectedPolicies   int
	}{
		"test.sql": {
			sql:                testSQL,
			expectedTables:     2,
			expectedRLSEnables: 1,
			expectedPolicies:   1,
		},
		"test2.sql": {
			sql:                test2SQL,
			expectedTables:     2,
			expectedRLSEnables: 1,
			expectedPolicies:   1,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			tables, rlsEnables, policies, err := ParseSQL(name, tc.sql)

			assert.NoError(t, err)
			assert.Len(t, tables, tc.expectedTables)
			assert.Len(t, rlsEnables, tc.expectedRLSEnables)
			assert.Len(t, policies, tc.expectedPolicies)
		})
	}
}

func TestParseSQL_LocationInfo(t *testing.T) {
	// 位置情報が正しく設定されるかテスト
	sql := `CREATE TABLE accounts (id int);
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY account_policy ON accounts USING (true);`

	tables, rlsEnables, policies, err := ParseSQL("test.sql", sql)

	assert.NoError(t, err)
	assert.Len(t, tables, 1)
	assert.Len(t, rlsEnables, 1)
	assert.Len(t, policies, 1)

	// ファイル名の検証
	assert.Equal(t, "test.sql", tables[0].Filename)
	assert.Equal(t, "test.sql", rlsEnables[0].Filename)
	assert.Equal(t, "test.sql", policies[0].Filename)

	// 位置情報の検証（正確な値ではなく、順序関係のみ検証）
	assert.Less(t, tables[0].Line, rlsEnables[0].Line)
	assert.Less(t, rlsEnables[0].Line, policies[0].Line)
}

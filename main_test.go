package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSQL(t *testing.T) {
	testCases := map[string]struct {
		input            string
		expectTableCount int
	}{
		"not contain create table": {
			input:            ``,
			expectTableCount: 0,
		},
		"create table only": {
			input: `CREATE TABLE A (
			id int
			);`,
			expectTableCount: 1,
		},
	}
	for name, testCase := range testCases {
		tables, _, _, err := ParseSQL("test.sql", testCase.input)
		assert.NoError(t, err)
		assert.Len(t, tables, testCase.expectTableCount, name)
	}
}

func TestValidateRLSMissingEnable(t *testing.T) {
	input := `CREATE TABLE accounts (id int, manager text);`
	tables, rlsEnables, policies, _ := ParseSQL("test.sql", input)

	result := ValidateRLS(tables, rlsEnables, policies, []string{})
	assert.Len(t, result, 1)
	assert.Equal(t, "accounts", result[0].TableName)
	assert.Equal(t, "rls-not-enabled", result[0].RuleID)
}

func TestValidateRLSMissingPolicy(t *testing.T) {
	input := `
	CREATE TABLE accounts (id int, manager text);
	ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
	`
	tables, rlsEnables, policies, _ := ParseSQL("test.sql", input)

	result := ValidateRLS(tables, rlsEnables, policies, []string{})
	assert.Len(t, result, 1)
	assert.Equal(t, "accounts", result[0].TableName)
	assert.Equal(t, "rls-no-policy", result[0].RuleID)
}

func TestValidateRLSCorrect(t *testing.T) {
	input := `
	CREATE TABLE accounts (id int, manager text);
	ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
	CREATE POLICY account_managers ON accounts USING (manager = current_user);
	`
	tables, rlsEnables, policies, _ := ParseSQL("test.sql", input)

	result := ValidateRLS(tables, rlsEnables, policies, []string{})
	assert.Len(t, result, 0)
}

func TestValidateRLSExcludedTable(t *testing.T) {
	input := `CREATE TABLE accounts (id int, manager text);`
	tables, rlsEnables, policies, _ := ParseSQL("test.sql", input)

	result := ValidateRLS(tables, rlsEnables, policies, []string{"accounts"})
	assert.Len(t, result, 0)
}

func TestValidateRLSMultipleTables(t *testing.T) {
	input := `
	CREATE TABLE accounts (id int, manager text);
	CREATE TABLE users (id int, name text);
	ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
	CREATE POLICY account_managers ON accounts USING (manager = current_user);
	`
	tables, rlsEnables, policies, _ := ParseSQL("test.sql", input)

	result := ValidateRLS(tables, rlsEnables, policies, []string{})
	assert.Len(t, result, 1)
	assert.Equal(t, "users", result[0].TableName)
}

// TestRunLinterWithSingleSource は単一ソースに対するリンター実行をテストする
func TestRunLinterWithSingleSource(t *testing.T) {
	testCases := map[string]struct {
		input          string
		filename       string
		excludedTables []string
		expectError    bool
		expectOutput   string // JSONの期待出力（または部分文字列）
	}{
		"missing RLS enable": {
			input:          `CREATE TABLE accounts (id int, manager text);`,
			filename:       "test.sql",
			excludedTables: []string{},
			expectError:    true,
			expectOutput:   `"rule_id": "rls-not-enabled"`,
		},
		"missing policy": {
			input:          `CREATE TABLE accounts (id int); ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;`,
			filename:       "test.sql",
			excludedTables: []string{},
			expectError:    true,
			expectOutput:   `"rule_id": "rls-no-policy"`,
		},
		"correct RLS": {
			input:          `CREATE TABLE accounts (id int); ALTER TABLE accounts ENABLE ROW LEVEL SECURITY; CREATE POLICY p ON accounts USING (true);`,
			filename:       "test.sql",
			excludedTables: []string{},
			expectError:    false,
			expectOutput:   ``,
		},
		"excluded table": {
			input:          `CREATE TABLE accounts (id int);`,
			filename:       "test.sql",
			excludedTables: []string{"accounts"},
			expectError:    false,
			expectOutput:   ``,
		},
		"multiple tables": {
			input: `
			CREATE TABLE accounts (id int, manager text);
			CREATE TABLE users (id int, name text);
			ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
			CREATE POLICY account_managers ON accounts USING (manager = current_user);
			`,
			filename:       "test.sql",
			excludedTables: []string{},
			expectError:    true,
			expectOutput:   `"table_name": "users"`,
		},
		"stdin file": {
			input:          `CREATE TABLE accounts (id int, manager text);`,
			filename:       "stdin",
			excludedTables: []string{},
			expectError:    true,
			expectOutput:   `"file": "stdin"`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// 入力と出力のバッファを準備
			inBuf := strings.NewReader(tc.input)
			outBuf := &bytes.Buffer{}

			// RunLinter関数を実行
			options := LinterOptions{
				Sources: []SourceFile{
					{
						Reader:   inBuf,
						Filename: tc.filename,
					},
				},
				Writer:         outBuf,
				ExcludedTables: tc.excludedTables,
			}
			err := RunLinter(options)

			// エラーの検証
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// 出力の検証
			output := outBuf.String()
			if tc.expectOutput != "" {
				assert.Contains(t, output, tc.expectOutput)
			} else {
				assert.Empty(t, output)
			}
		})
	}
}

// TestRunLinterWithMultipleSources は複数ソースに対するリンター実行をテストする
func TestRunLinterWithMultipleSources(t *testing.T) {
	// テスト用のSQL内容を定義
	file1Content := `CREATE TABLE accounts (id int, manager text);
CREATE TABLE users (id int, name text);
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY account_managers ON accounts USING (manager = current_user);`

	file2Content := `CREATE TABLE products (id int, name text, price int);
CREATE TABLE orders (id int, product_id int, quantity int);
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
CREATE POLICY product_policy ON products USING (true);`

	// 出力をキャプチャするためのバッファ
	outBuf := &bytes.Buffer{}

	// strings.Reader を使用して入力を準備
	file1Reader := strings.NewReader(file1Content)
	file2Reader := strings.NewReader(file2Content)

	// 複数ソースを処理
	options := LinterOptions{
		Sources: []SourceFile{
			{
				Reader:   file1Reader,
				Filename: "virtual_file1.sql", // 仮想的なファイル名
			},
			{
				Reader:   file2Reader,
				Filename: "virtual_file2.sql", // 仮想的なファイル名
			},
		},
		Writer:         outBuf,
		ExcludedTables: []string{},
	}
	err := RunLinter(options)

	// 検証
	assert.Error(t, err)
	assert.Contains(t, outBuf.String(), `"table_name": "users"`)
	assert.Contains(t, outBuf.String(), `"table_name": "orders"`)
	assert.Contains(t, outBuf.String(), "virtual_file1.sql")
	assert.Contains(t, outBuf.String(), "virtual_file2.sql")
}

// TestRunLinterWithExcludedTables は除外テーブルオプションを使用したリンター実行をテストする
func TestRunLinterWithExcludedTables(t *testing.T) {
	// SQLの内容を直接定義
	sqlContent := `CREATE TABLE accounts (id int, manager text);
CREATE TABLE users (id int, name text);`

	// 出力をキャプチャするためのバッファ
	outBuf := &bytes.Buffer{}

	// 除外オプションを指定してRunLinter関数を実行
	options := LinterOptions{
		Sources: []SourceFile{
			{
				Reader:   strings.NewReader(sqlContent),
				Filename: "test_exclude.sql", // 仮想的なファイル名
			},
		},
		Writer:         outBuf,
		ExcludedTables: []string{"users"},
	}
	err := RunLinter(options)

	// 検証
	assert.Error(t, err) // RLS設定の不足があるためエラーが発生する
	assert.Contains(t, outBuf.String(), `"table_name": "accounts"`)
	assert.NotContains(t, outBuf.String(), `"table_name": "users"`)
}

// TestMultiplePolicies は1つのテーブルに対して複数のポリシーがある場合をテストする
func TestMultiplePolicies(t *testing.T) {
	input := `
	CREATE TABLE accounts (id int, manager text, department text);
	ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
	CREATE POLICY manager_policy ON accounts USING (manager = current_user);
	CREATE POLICY department_policy ON accounts USING (department = current_setting('app.department'));
	`
	tables, rlsEnables, policies, err := ParseSQL("test.sql", input)
	assert.NoError(t, err)

	// テーブルの検証
	assert.Len(t, tables, 1, "テーブルが1つ検出されるべきです")
	assert.Equal(t, "accounts", tables[0].TableName)

	// RLS有効化の検証
	assert.Len(t, rlsEnables, 1, "RLS有効化が1つ検出されるべきです")
	assert.Equal(t, "accounts", rlsEnables[0].TableName)

	// ポリシーの検証
	assert.Len(t, policies, 2, "ポリシーが2つ検出されるべきです")

	// ポリシー名の検証
	policyNames := []string{}
	for _, policy := range policies {
		policyNames = append(policyNames, policy.PolicyName)
	}
	assert.Contains(t, policyNames, "manager_policy", "manager_policyが検出されるべきです")
	assert.Contains(t, policyNames, "department_policy", "department_policyが検出されるべきです")

	// 検証結果
	results := ValidateRLS(tables, rlsEnables, policies, []string{})
	assert.Len(t, results, 0, "RLS設定の不足は検出されないべきです")
}

// TestMultiByteCharacters は日本語や絵文字などのマルチバイト文字を含むSQLをテストする
func TestMultiByteCharacters(t *testing.T) {
	testCases := map[string]struct {
		input           string
		expectTableName string
	}{
		"japanese table name": {
			input:           `CREATE TABLE "ユーザー" (id int, name text);`,
			expectTableName: "ユーザー",
		},
		"japanese column name": {
			input:           `CREATE TABLE users (id int, "名前" text);`,
			expectTableName: "users",
		},
		"emoji in table name": {
			input:           `CREATE TABLE "user_😊" (id int, name text);`,
			expectTableName: "user_😊",
		},
		"japanese comment": {
			input:           `CREATE TABLE users (id int, name text); -- ユーザーテーブル`,
			expectTableName: "users",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// パース
			tables, rlsEnables, policies, err := ParseSQL("test.sql", tc.input)
			assert.NoError(t, err, "マルチバイト文字を含むSQLのパースに失敗しました")

			// 検証
			assert.Len(t, tables, 1, "テーブルが1つ検出されるべきです")
			if len(tables) > 0 {
				assert.Equal(t, tc.expectTableName, tables[0].TableName, "テーブル名が一致しません")
			}

			// 検証結果
			results := ValidateRLS(tables, rlsEnables, policies, []string{})
			assert.Len(t, results, 1, "RLS設定の不足が検出されるべきです")
			if len(results) > 0 {
				assert.Equal(t, tc.expectTableName, results[0].TableName, "検証結果のテーブル名が一致しません")
				assert.Equal(t, "rls-not-enabled", results[0].RuleID, "RLSが有効化されていないことが検出されるべきです")
			}
		})
	}
}

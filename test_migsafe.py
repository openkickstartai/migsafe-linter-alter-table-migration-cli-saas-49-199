"""Tests for MigSafe rule engine."""
from rules import analyze, risk_score, estimate_lock_ms


def test_drop_table_detected():
    findings = analyze("DROP TABLE users;")
    assert len(findings) == 1
    assert findings[0].rule_id == "BAN001"
    assert findings[0].severity == "critical"
    assert findings[0].lock_type == "ACCESS EXCLUSIVE"


def test_drop_column_detected():
    findings = analyze("ALTER TABLE users DROP COLUMN age;")
    assert any(f.rule_id == "BAN002" for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_add_not_null_without_default_is_dangerous():
    sql = "ALTER TABLE orders ADD COLUMN status varchar(20) NOT NULL;"
    findings = analyze(sql)
    assert any(f.rule_id == "LCK001" for f in findings)


def test_add_not_null_with_default_is_safe():
    sql = "ALTER TABLE orders ADD COLUMN status varchar(20) NOT NULL DEFAULT 'pending';"
    findings = analyze(sql)
    assert not any(f.rule_id == "LCK001" for f in findings)


def test_create_index_without_concurrently():
    findings = analyze("CREATE INDEX idx_email ON users(email);")
    assert any(f.rule_id == "LCK002" for f in findings)


def test_create_index_concurrently_is_safe():
    findings = analyze("CREATE INDEX CONCURRENTLY idx_email ON users(email);")
    assert not any(f.rule_id == "LCK002" for f in findings)


def test_foreign_key_without_not_valid():
    sql = "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);"
    findings = analyze(sql)
    assert any(f.rule_id == "LCK003" for f in findings)


def test_foreign_key_with_not_valid_is_safe():
    sql = "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID;"
    findings = analyze(sql)
    assert not any(f.rule_id == "LCK003" for f in findings)


def test_alter_column_type():
    sql = "ALTER TABLE big_table ALTER COLUMN price TYPE numeric;"
    findings = analyze(sql, rows=5_000_000)
    lck = [f for f in findings if f.rule_id == "LCK004"]
    assert len(lck) == 1
    assert lck[0].lock_ms is not None
    assert lck[0].lock_ms > 100  # 5M rows should give significant estimate


def test_rename_table():
    findings = analyze("ALTER TABLE users RENAME TO customers;")
    assert any(f.rule_id == "BAN003" for f in findings)
    assert any(f.severity == "medium" for f in findings)


def test_safe_migration_passes_cleanly():
    sql = """CREATE TABLE features (id serial PRIMARY KEY, name text);
    ALTER TABLE orders ADD COLUMN notes text;
    CREATE INDEX CONCURRENTLY idx_notes ON orders(notes);"""
    findings = analyze(sql)
    assert len(findings) == 0


def test_risk_score_scales():
    single = analyze("DROP TABLE users;")
    multi = analyze("DROP TABLE users; ALTER TABLE orders DROP COLUMN status;")
    assert 0 < risk_score(single) < risk_score(multi) <= 100


def test_risk_score_empty():
    assert risk_score([]) == 0


def test_estimate_lock_ms_with_rows():
    assert estimate_lock_ms(10, 1_000_000) == 110  # 1M/10k + 10 = 110
    assert estimate_lock_ms(None, 1_000_000) == 100  # 1M/10k = 100
    assert estimate_lock_ms(50, 0) == 50  # no rows, return base
    assert estimate_lock_ms(None, 0) is None  # no info at all

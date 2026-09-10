from tools import arsenal


def test_registry_is_scoped_to_tool_rows():
    rows = arsenal.load_registry()
    assert len(rows) >= 70
    assert all(set(row) == {"name", "category", "hint", "upstream"} for row in rows)
    assert not any(row["name"] in {"Categories", "Status", "Install hint"} for row in rows)


def test_profiles_are_selective_and_all_excludes_credentials():
    rows = arsenal.load_registry()
    core = arsenal.profile_rows(rows, "core")
    full = arsenal.profile_rows(rows, "all")
    credential = arsenal.profile_rows(rows, "credential-attack")
    assert core
    assert credential
    assert all(row["category"] != "cred" for row in full)
    assert all(row["category"] == "cred" for row in credential)


def test_status_reports_json_shape():
    rows = arsenal.load_registry()
    installed, missing = arsenal.status(rows, "recon")
    assert installed or missing
    assert all("path" in row for row in installed + missing)


def test_credential_profile_requires_acknowledgement(capsys):
    assert arsenal.install(arsenal.load_registry(), "credential-attack", True, True, False) == 2
    assert "opt-in" in capsys.readouterr().out

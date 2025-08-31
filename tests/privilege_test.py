def test_privilege(base_url, session, admin_creds):
    if not admin_creds:
        return {"error": "Admin creds not provided"}
    # Simulation only: real test would compare low-user vs admin access
    return {"result": "Privilege escalation attempted (simulated)"}

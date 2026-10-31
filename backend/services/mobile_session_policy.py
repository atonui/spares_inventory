"""Server-side helpers for resolving native mobile session lifetime policy."""


def effective_mobile_session_duration_hours(conn, organization_id) -> int:
    """Return the organization duration capped by the platform maximum.

    Organization settings are protected by RLS, so the resolved organization is
    applied only as transaction-local context for this read and the previous
    context is restored before returning.
    """
    maximum_row = conn.execute(
        "SELECT setting_value FROM system_settings WHERE setting_key = 'mobile_session_max_duration_hours'"
    ).fetchone()
    try:
        maximum = max(1, min(720, int(maximum_row["setting_value"]))) if maximum_row else 720
    except (TypeError, ValueError):
        maximum = 720
    if organization_id is None:
        return maximum

    prior_scope = conn.execute(
        "SELECT current_setting('app.organization_id', true) AS organization_id"
    ).fetchone()["organization_id"]
    conn.execute("SELECT set_config('app.organization_id', %s, true)", (str(organization_id),))
    try:
        row = conn.execute(
            "SELECT mobile_session_duration_hours FROM organization_settings WHERE organization_id = %s",
            (organization_id,),
        ).fetchone()
    finally:
        conn.execute("SELECT set_config('app.organization_id', %s, true)", (prior_scope or "",))
    try:
        return min(maximum, max(1, int(row["mobile_session_duration_hours"]))) if row else maximum
    except (TypeError, ValueError):
        return maximum

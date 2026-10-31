"""Version 20: platform administrators are separate from tenant members."""

VERSION = 20
NAME = "platform_tenant_identity_separation"

SQL = (
    "LOCK TABLE organization_memberships IN SHARE ROW EXCLUSIVE MODE",
    "LOCK TABLE platform_admins IN SHARE ROW EXCLUSIVE MODE",
    # Preserve an active owner before removing any dual-role memberships.
    """DO $$
       BEGIN
           IF EXISTS (
               SELECT 1 FROM organization_memberships AS om
               JOIN platform_admins AS pa ON pa.user_id = om.user_id
               WHERE om.is_active AND om.company_role = 'owner'
                 AND NOT EXISTS (
                     SELECT 1 FROM organization_memberships AS other_owner
                     WHERE other_owner.organization_id = om.organization_id
                       AND other_owner.is_active = TRUE
                       AND other_owner.company_role = 'owner'
                       AND other_owner.user_id <> om.user_id
                       AND NOT EXISTS (
                           SELECT 1 FROM platform_admins AS other_platform_admin
                           WHERE other_platform_admin.user_id = other_owner.user_id
                       )
                 )
           ) THEN
               RAISE EXCEPTION 'Platform-admin membership separation requires promoting another active tenant owner first';
           END IF;
       END
       $$""",
    """DELETE FROM organization_memberships AS om
       USING platform_admins AS pa
       WHERE pa.user_id = om.user_id""",
    """CREATE FUNCTION enforce_platform_tenant_identity_separation()
       RETURNS TRIGGER LANGUAGE plpgsql AS $$
       BEGIN
           PERFORM pg_advisory_xact_lock(NEW.user_id);
           IF TG_TABLE_NAME = 'organization_memberships' THEN
               IF EXISTS (SELECT 1 FROM platform_admins WHERE user_id = NEW.user_id) THEN
                   RAISE EXCEPTION 'Platform administrators cannot have tenant memberships'
                       USING ERRCODE = '23514';
               END IF;
           ELSE
               IF EXISTS (SELECT 1 FROM organization_memberships WHERE user_id = NEW.user_id) THEN
                   RAISE EXCEPTION 'Tenant members cannot be platform administrators'
                       USING ERRCODE = '23514';
               END IF;
           END IF;
           RETURN NEW;
       END
       $$""",
    """CREATE TRIGGER organization_memberships_exclude_platform_admins
       BEFORE INSERT OR UPDATE OF user_id ON organization_memberships
       FOR EACH ROW EXECUTE FUNCTION enforce_platform_tenant_identity_separation()""",
    """CREATE TRIGGER platform_admins_exclude_tenant_members
       BEFORE INSERT OR UPDATE OF user_id ON platform_admins
       FOR EACH ROW EXECUTE FUNCTION enforce_platform_tenant_identity_separation()""",
)

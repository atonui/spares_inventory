"""Version 20: platform administrators are separate from tenant members."""

VERSION = 20
NAME = "platform_tenant_identity_separation"

SQL = (
    # Protect active organizations before removing any dual-role memberships.
    """DO $$
       BEGIN
           IF EXISTS (
               SELECT 1 FROM organization_memberships AS om
               JOIN platform_admins AS pa ON pa.user_id = om.user_id
               JOIN organizations AS o ON o.id = om.organization_id
               WHERE om.is_active AND om.company_role = 'owner' AND o.is_active
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

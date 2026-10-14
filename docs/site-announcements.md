# Site announcements and configuration validation

Superadmin announcements are public notices. The existing read endpoint remains
public: do not put confidential information in broadcasts. Superadmin role,
active-session revalidation and CSRF checks still protect creating and removing
notices. The server trims messages, requires 1–2000 characters and accepts only
info, warning or danger. Display uses text rather than interpreted HTML.

All five pages load the shared announcement banner independently of their account
controller. It checks on page initialization, every 60 seconds while visible and
when a hidden page becomes visible. Removal clears the banner on the next check.
Loading failures preserve the last notice, show a stale-data warning and offer
Retry. Page teardown releases the polling timer and visibility listener. The
superadmin editor also exposes loading errors and Retry. This is periodic delivery,
not push delivery; offline pages cannot receive changes.

Configuration writes enforce positive integers and the UI's upper bounds:
100 login attempts, 1440 lockout minutes, 720 session hours, 365 remember-me days.
Calibration reminders use the same 1–365 day range as the equipment endpoint.
Authentication policy changes apply to new login decisions and new sessions;
already-issued sessions retain their original expiry.

Validation uses disposable databases and shipped-page JavaScript tests. Production
configuration and broadcasts are not altered by the verification workflow.
Rendered signed-in desktop/mobile checks remain subject to browser access.

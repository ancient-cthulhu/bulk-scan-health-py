"""
Modules behind scan_health.py. Run the tool with `python scan_health.py`;
nothing here is meant to be run directly.

Single application and single scan (--app, --app-id, --app-guid, --scan):
    app_report            resolution, collection, response cache, run()
    app_report_analytics  verdicts, action plan, duration, cadence, findings, diffs
    app_report_html       the report.html renderer

Tenant (bulk runs):
    tenant_report         snapshots (write, read, compare) and the end-of-run hook
    tenant_analytics      tenant KPIs, fix list, movement and trends
    tenant_report_html    the tenant_report.html renderer and its one script

Shared:
    report_ui             escaping, safe links, chips, SVG chart helpers
    report_kit            two-lens components and the report stylesheet
    output_layout         the scan_health_output folder layout and run folders
"""

"""Report rendering for jshunter: JSON dump + human-readable text."""
import json


def to_json(report):
    return json.dumps(report, indent=2)


def _sev_rank(sev):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


def to_text(report):
    lines = []
    s = report["summary"]
    lines.append("jshunter report for {0}".format(report["target"]))
    lines.append("=" * 60)
    lines.append("JS files scanned : {0} ({1} failed)".format(
        s["files_scanned"], s["files_failed"]))
    lines.append("Secrets found    : {0}".format(s["secrets_found"]))
    lines.append("Endpoints found  : {0}".format(s["endpoints_found"]))
    if s["by_severity"]:
        sev_str = ", ".join("{0}:{1}".format(k, s["by_severity"][k])
                            for k in sorted(s["by_severity"], key=_sev_rank))
        lines.append("By severity      : {0}".format(sev_str))
    lines.append("")

    for f in report["js_files"]:
        lines.append("--- {0}".format(f["url"]))
        if f.get("error"):
            lines.append("  [!] {0}".format(f["error"]))
            continue
        if not f["secrets"] and not f["endpoints"]:
            lines.append("  (clean)")
        for sec in sorted(f["secrets"], key=lambda x: _sev_rank(x["severity"])):
            lines.append("  [{0}] {1}: {2}".format(sec["severity"], sec["rule"], sec["preview"]))
            lines.append("        {0}".format(sec["description"]))
        if f["endpoints"]:
            lines.append("  endpoints:")
            for ep in f["endpoints"][:25]:
                lines.append("    ({0}) {1}".format(ep["kind"], ep["value"]))
            if len(f["endpoints"]) > 25:
                lines.append("    ... +{0} more".format(len(f["endpoints"]) - 25))
        if f["sourcemaps"]:
            lines.append("  sourcemaps (may leak original source):")
            for sm in f["sourcemaps"]:
                lines.append("    {0}".format(sm))
        lines.append("")

    lines.append("NOTE: verify every finding manually before reporting. "
                 "A matched pattern is a lead, not a vulnerability.")
    return "\n".join(lines)

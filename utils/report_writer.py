import json, os, time
from jinja2 import Template

def write_reports(base_url: str, results: list, template_path: str, out_dir: str, domain: str,
                  exploited: list = None, filename_suffix: str = ""):
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    json_out = os.path.join(out_dir, f"{domain}_csrf_{ts}{filename_suffix}.json")
    html_out = os.path.join(out_dir, f"{domain}_csrf_{ts}{filename_suffix}.html")

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump({
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "base_url": base_url,
            "results": results,
            "exploited": exploited or []
        }, f, indent=2)

    successes = sum(1 for r in results if r.get("status") and int(r["status"]) < 400)

    with open(template_path, "r", encoding="utf-8") as t:
        tmpl = Template(t.read())

    html = tmpl.render(
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        base_url=base_url,
        actions_count=len(set([r["action"] for r in results])) if results else 0,
        total_vectors=len(results),
        successes=successes,
        results=results,
        exploited=exploited or []
    )
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(html)

    return json_out, html_out

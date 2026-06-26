#!/usr/bin/env python3
"""
runtime attack scorecard for the OWASP Benchmark protected by ByteHide Runtime.

The Benchmark crawler sends BENIGN inputs (it targets SAST/IAST), so it cannot measure a
pattern-based runtime. This script instead drives every test case of the 6 runtime-applicable
categories twice:

  1. ATTACK pass  : send a category-appropriate real exploit to each real-vulnerability
                    endpoint  -> a 403 means the runtime BLOCKED the attack (recall / TPR).
  2. BENIGN pass  : replay the crawler's own benign values to EVERY endpoint
                    -> a 403 here is a FALSE POSITIVE (blocking legitimate traffic).

IMPORTANT details that make the measurement valid:
 - Each request uses a UNIQUE User-Agent so it is its OWN runtime session (session id =
   SHA-256(ip|user-agent)); otherwise the first detected attack blocks the shared session
   and every later request returns 403 by cascade.
 - The attack payload is injected into EVERY input element the crawler lists for a test
   (a test often has several params, e.g. password/email/BenchmarkTestNNNNN, and only one
   is the vulnerable sink). Sink-confirmed detectors (SQLi/XPath) only see the param the
   servlet actually concatenates into the query, so the payload must reach all of them.
"""
import csv, os, re, sys, ssl, collections, urllib.request, urllib.parse, urllib.error

# Benchmark repo root: this script lives at <repo>/bytehide-runtime/attack/, so go up three levels.
# Override with BENCH_HOME if you run it from elsewhere.
BENCH   = os.environ.get("BENCH_HOME") or os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CRAWLER = os.path.join(BENCH, "data", "benchmark-crawler-http.xml")
EXPECTED= os.path.join(BENCH, "expectedresults-1.2.csv")
BASE_OVERRIDE = os.environ.get("BENCH_URL")           # e.g. https://localhost:9443/benchmark
CATS = {"sqli", "xss", "pathtraver", "cmdi", "ldapi", "xpathi"}
TIMEOUT = 15

# Real attack payloads per category (one representative high-signal exploit each).
ATTACK = {
    "sqli":       "' OR '1'='1' --",
    "xss":        "<script>alert(document.cookie)</script>",
    "pathtraver": "../../../../../../etc/passwd",
    "cmdi":       "x; cat /etc/passwd",
    "ldapi":      "*)(uid=*))(|(uid=*",
    "xpathi":     "' or '1'='1",
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def parse_expected():
    exp = {}
    with open(EXPECTED) as f:
        for r in csv.reader(f):
            if not r or r[0].startswith("#"):
                continue
            exp[r[0].strip()] = (r[1].strip(), r[2].strip() == "true")
    return exp

def parse_crawler():
    xml = open(CRAWLER).read()
    out = []
    for b in re.findall(r"<benchmarkTest\b.*?</benchmarkTest>", xml, re.S):
        url = re.search(r'URL="([^"]+)"', b).group(1)
        tc  = re.search(r'tcName="([^"]+)"', b).group(1)
        els = re.findall(r'<(cookie|header|getparam|formparam)\s+name="([^"]*)"\s+value="([^"]*)"', b)
        if not els:
            continue
        out.append({"tc": tc, "url": url,
                    "elements": [{"kind": k, "name": n, "benign": v} for k, n, v in els]})
    return out

def primary_channel(case):
    """Channel of the element named after the test (the usual sink param), else the first."""
    for el in case["elements"]:
        if el["name"] == case["tc"]:
            return el["kind"]
    return case["elements"][0]["kind"]

def only_header(case):
    return all(el["kind"] == "header" for el in case["elements"])

def send(case, payload, tag):
    """Issue ONE request. payload=None -> benign (each element's own value); else attack
    payload injected into EVERY element. `tag` makes the session unique per request."""
    url = case["url"]
    if BASE_OVERRIDE:
        url = re.sub(r"^https?://[^/]+/benchmark", BASE_OVERRIDE.rstrip("/"), url)
    headers = {"User-Agent": "runtime-scorecard/%s/%s" % (case["tc"], tag)}
    getparams, formparams, cookies = {}, {}, []
    method = "GET"
    for el in case["elements"]:
        k = el["kind"]; nm = el["name"]; benign = el["benign"]
        # Name-injection slot: some servlets read the NAME of the param whose VALUE is the test
        # marker (== tcName) and use that name as the SQL input. To exploit, put the payload in the
        # NAME and keep the marker as the value so the servlet still finds it.
        if payload is not None and benign == case["tc"] and k in ("getparam", "formparam"):
            send_name, send_val = payload, benign
        else:
            send_name, send_val = nm, (payload if payload is not None else benign)
        if k == "getparam":
            getparams[send_name] = send_val
        elif k == "formparam":
            formparams[send_name] = send_val; method = "POST"
        elif k == "header":
            headers[send_name] = send_val
        elif k == "cookie":
            cookies.append((send_name, send_val))
    if getparams:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(getparams)
    data = None
    if formparams:
        data = urllib.parse.urlencode(formparams).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        method = "POST"
    if cookies:
        headers["Cookie"] = "; ".join("%s=%s" % (n, urllib.parse.quote(v, safe="")) for n, v in cookies)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

def main():
    exp = parse_expected()
    cases = [c for c in parse_crawler() if exp.get(c["tc"], ("", False))[0] in CATS]
    for c in cases:
        c["cat"], c["real"] = exp[c["tc"]]
    print("Loaded %d test cases across %s" % (len(cases), ", ".join(sorted(CATS))))
    print("Base URL override (BENCH_URL): %s" % (BASE_OVERRIDE or "(none -> crawler URLs as-is)"))

    probe = send(cases[0], None, "probe")
    print("Probe status: %s" % probe)
    if probe == 0:
        print("\nERROR: could not reach the Benchmark. Is it up at the right port?")
        sys.exit(1)

    rows = []
    tp = collections.Counter(); tp_tot = collections.Counter()      # attack blocked on real vulns
    fp = collections.Counter(); fp_tot = collections.Counter()      # benign blocked anywhere
    ob = collections.Counter(); ob_tot = collections.Counter()      # attack blocked on safe sinks (info)
    hdr_only_miss = collections.Counter()                            # real-vuln misses that are header-only

    for i, c in enumerate(cases, 1):
        cat = c["cat"]
        atk = send(c, ATTACK[cat], "atk"); blocked_atk = (atk == 403)
        ben = send(c, None, "ben");        blocked_ben = (ben == 403)
        ch = primary_channel(c); ho = only_header(c)
        if c["real"]:
            tp_tot[cat] += 1; tp[cat] += blocked_atk
            if not blocked_atk and ho:
                hdr_only_miss[cat] += 1
        else:
            ob_tot[cat] += 1; ob[cat] += blocked_atk
        fp_tot[cat] += 1; fp[cat] += blocked_ben
        rows.append([c["tc"], cat, c["real"], ch, ho, atk, blocked_atk, ben, blocked_ben])
        if i % 200 == 0:
            print("  ...%d/%d" % (i, len(cases)))

    with open(os.path.join(os.path.dirname(__file__), "scorecard.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["test", "category", "real_vuln", "primary_channel", "header_only",
                    "attack_status", "attack_blocked", "benign_status", "benign_blocked"])
        w.writerows(rows)

    print("\n==================== ByteHide Runtime scorecard ====================")
    print("%-11s | recall (attacks blocked) | false-pos (benign) | header-only misses" % "category")
    print("-" * 84)
    for cat in sorted(CATS):
        rec = "%d/%d (%.0f%%)" % (tp[cat], tp_tot[cat], 100*tp[cat]/tp_tot[cat]) if tp_tot[cat] else "n/a"
        fpr = "%d/%d (%.0f%%)" % (fp[cat], fp_tot[cat], 100*fp[cat]/fp_tot[cat]) if fp_tot[cat] else "n/a"
        print("%-11s | %-24s | %-18s | %d" % (cat, rec, fpr, hdr_only_miss[cat]))
    print("-" * 84)
    RT, RTt = sum(tp.values()), sum(tp_tot.values())
    FT, FTt = sum(fp.values()), sum(fp_tot.values())
    print("%-11s | %-24s | %-18s | %d" % ("TOTAL",
          "%d/%d (%.1f%%)" % (RT, RTt, 100*RT/RTt),
          "%d/%d (%.1f%%)" % (FT, FTt, 100*FT/FTt), sum(hdr_only_miss.values())))
    print("\nWrote per-case detail to scorecard.csv")
    print("recall             = % of REAL-VULN endpoints where the exploit got a 403")
    print("false-pos          = % of endpoints that 403'd the BENIGN values (lower better)")
    print("header-only misses = real-vuln misses delivered ONLY via a custom header")
    print("                     (runtime scans only Referer/Origin headers by design)")

if __name__ == "__main__":
    main()

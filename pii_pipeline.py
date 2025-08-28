#!/usr/bin/env python3
"""
pii_pipeline.py

Phase 1 pipeline:
CSV -> detect Aadhaar/PAN/Phone/Email/CreditCard -> validate -> de-identify (mask or HMAC-tokenize) -> output CSV + JSON report

Usage:
    python pii_pipeline.py -i input.csv -o masked.csv -r report.json --chunksize 2000 --masking-mode mask --hmac-key secret123
"""

import argparse
import csv
import hashlib
import hmac
import json
import re
from typing import Dict, Optional

import pandas as pd

# ----- Regexes -----
RE_AADHAAR_STRICT = re.compile(r'^\d{12}$')
RE_AADHAAR_ANY = re.compile(r'\b\d{12}\b')
RE_PAN = re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$')
RE_PAN_ANY = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.IGNORECASE)
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
RE_PHONE = re.compile(r'(?:\+91[\-\s]?|0)?([6-9]\d{9})\b')
RE_CREDIT_CARD = re.compile(r'\b(?:\d[ -]*?){13,19}\b')  # typical credit card length range

# ----- Verhoeff algorithm for Aadhaar checksum -----
_d = [[0,1,2,3,4,5,6,7,8,9], [1,2,3,4,0,6,7,8,9,5], [2,3,4,0,1,7,8,9,5,6], [3,4,0,1,2,8,9,5,6,7], [4,0,1,2,3,9,5,6,7,8], [5,9,8,7,6,0,4,3,2,1], [6,5,9,8,7,1,0,4,3,2], [7,6,5,9,8,2,1,0,4,3], [8,7,6,5,9,3,2,1,0,4], [9,8,7,6,5,4,3,2,1,0]]
_p = [[0,1,2,3,4,5,6,7,8,9], [1,5,7,6,2,8,3,0,9,4], [5,8,0,3,7,9,6,1,4,2], [8,9,1,6,0,4,3,5,2,7], [9,4,5,3,1,2,6,8,7,0], [4,2,8,6,5,7,3,9,0,1], [2,7,9,3,8,0,6,4,1,5], [7,0,4,6,9,1,3,2,5,8]]
_inv = [0,4,3,2,1,5,6,7,8,9]

def verhoeff_check(number: str) -> bool:
    try:
        c = 0
        for i, ch in enumerate(reversed(number)):
            c = _d[c][_p[i % 8][int(ch)]]
        return _inv[c] == 0
    except Exception:
        return False

# ----- Luhn algorithm for Credit Card -----
def luhn_check(number: str) -> bool:
    try:
        digits = [int(d) for d in re.sub(r'\D', '', number)]
        checksum = 0
        parity = len(digits) % 2
        for i, d in enumerate(digits):
            if i % 2 == parity:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
    except Exception:
        return False

# ----- Masking / Tokenization -----
def mask_aadhaar(a: str) -> str:
    s = re.sub(r'\D', '', a)
    if len(s) != 12:
        return 'X' * len(a)
    return 'XXXX-XXXX-' + s[-4:]

def mask_pan(p: str) -> str:
    px = p.upper()
    if len(px) != 10:
        return 'X' * len(px)
    return 'XXXXX' + px[5:]

def mask_phone(ph: str) -> str:
    digits = re.sub(r'\D', '', ph)
    if len(digits) < 4:
        return 'X' * len(ph)
    return 'X' * (len(digits) - 4) + digits[-4:]

def mask_email(e: str) -> str:
    m = RE_EMAIL.search(e)
    if not m:
        return 'X' * len(e)
    local, domain = e.split('@', 1)
    if len(local) <= 1:
        local_masked = 'X'
    elif len(local) == 2:
        local_masked = local[0] + 'X'
    else:
        local_masked = local[0] + 'X'*(len(local)-2) + local[-1]
    return f"{local_masked}@{domain}"

def mask_credit_card(cc: str) -> str:
    digits = re.sub(r'\D', '', cc)
    if len(digits) < 12:
        return 'X' * len(cc)
    return 'XXXX-XXXX-XXXX-' + digits[-4:]

def hmac_token(value: str, key: str) -> str:
    if value is None:
        return ''
    digest = hmac.new(key.encode('utf-8'), value.encode('utf-8'), hashlib.sha256).hexdigest()
    return 'TOK_' + digest[:32]

# ----- Detection & validation -----
def detect_types(value: str) -> Dict[str, str]:
    found = {}
    if value is None:
        return found
    s = str(value).strip()
    if not s:
        return found
    if RE_AADHAAR_STRICT.match(s):
        found['aadhaar'] = s
    else:
        m = RE_AADHAAR_ANY.search(s)
        if m:
            found['aadhaar'] = m.group(0)
    m = RE_PAN_ANY.search(s)
    if m:
        found['pan'] = m.group(0).upper()
    m = RE_EMAIL.search(s)
    if m:
        found['email'] = m.group(0)
    m = RE_PHONE.search(s)
    if m:
        found['phone'] = m.group(1)
    m = RE_CREDIT_CARD.search(s)
    if m:
        found['credit_card'] = re.sub(r'\D', '', m.group(0))
    return found

def validate_aadhaar(aadhaar_digits: str) -> bool:
    return bool(RE_AADHAAR_STRICT.match(aadhaar_digits) and verhoeff_check(aadhaar_digits))

def validate_pan(pan: str) -> bool:
    return bool(RE_PAN.match(pan.upper()))

def validate_credit_card(cc: str) -> bool:
    return luhn_check(cc)

# ----- Main pipeline -----
def process_csv(input_path: str, output_path: str, report_path: str, chunksize: int = 5000, masking_mode: str = 'mask', hmac_key: Optional[str] = None, pii_columns_hint: Optional[list] = None):
    report = {
        'total_rows_scanned': 0,
        'detections': {
            'aadhaar': {'found': 0, 'valid': 0, 'invalid': 0},
            'pan': {'found': 0, 'valid': 0, 'invalid': 0},
            'phone': {'found': 0},
            'email': {'found': 0},
            'credit_card': {'found': 0, 'valid': 0, 'invalid': 0}
        },
        'sample_audit': []
    }
    sample_audit_limit = 100

    first_chunk = True
    for chunk in pd.read_csv(input_path, chunksize=chunksize, dtype=str, keep_default_na=False, na_values=['']):
        out_rows = []
        for idx, row in chunk.iterrows():
            report['total_rows_scanned'] += 1
            row = row.fillna('')
            new_row = row.copy()
            row_detected = {}
            for col in row.index:
                cell = str(row[col])
                if cell.strip() == '':
                    continue
                det = detect_types(cell)
                if not det:
                    continue
                for t, match in det.items():
                    row_detected.setdefault(t, []).append({'column': col, 'value_sample': match})
                    if t in report['detections']:
                        report['detections'][t]['found'] += 1

                    valid = None
                    if t == 'aadhaar':
                        valid = validate_aadhaar(match)
                        report['detections']['aadhaar']['valid' if valid else 'invalid'] += 1
                    elif t == 'pan':
                        valid = validate_pan(match)
                        report['detections']['pan']['valid' if valid else 'invalid'] += 1
                    elif t == 'credit_card':
                        valid = validate_credit_card(match)
                        report['detections']['credit_card']['valid' if valid else 'invalid'] += 1

                    if masking_mode == 'mask':
                        if t == 'aadhaar':
                            masked = mask_aadhaar(match)
                        elif t == 'pan':
                            masked = mask_pan(match)
                        elif t == 'phone':
                            masked = mask_phone(match)
                        elif t == 'email':
                            masked = mask_email(match)
                        elif t == 'credit_card':
                            masked = mask_credit_card(match)
                        else:
                            masked = 'REDACTED'
                    else:
                        key = hmac_key or 'default_key'
                        masked = hmac_token(match, key)

                    try:
                        new_val = re.sub(re.escape(match), masked, cell)
                        new_row[col] = new_val
                        cell = new_val
                    except Exception:
                        new_row[col] = masked

            if row_detected and len(report['sample_audit']) < sample_audit_limit:
                audit_item = {'row_index_global': report['total_rows_scanned'], 'detected': []}
                for t, items in row_detected.items():
                    for it in items:
                        val = it['value_sample']
                        fingerprint = hmac_token(val, hmac_key or 'audit_default_key')
                        audit_item['detected'].append({'type': t, 'column': it['column'], 'fingerprint': fingerprint})
                report['sample_audit'].append(audit_item)

            out_rows.append(new_row)

        df_out = pd.DataFrame(out_rows)
        if first_chunk:
            df_out.to_csv(output_path, index=False, mode='w', quoting=csv.QUOTE_MINIMAL)
            first_chunk = False
        else:
            df_out.to_csv(output_path, index=False, mode='a', header=False, quoting=csv.QUOTE_MINIMAL)

    with open(report_path, 'w', encoding='utf-8') as rf:
        json.dump(report, rf, indent=2)

    print("Done. Output written to:", output_path)
    print("Report written to:", report_path)

# ----- CLI -----
def main():
    parser = argparse.ArgumentParser(description="PII detection + validation + masking pipeline (CSV).")
    parser.add_argument('-i', '--input', required=True, help='Input CSV file path')
    parser.add_argument('-o', '--output', required=True, help='Output masked CSV file path')
    parser.add_argument('-r', '--report', required=True, help='JSON report path')
    parser.add_argument('--chunksize', type=int, default=5000, help='CSV read chunksize for memory efficiency')
    parser.add_argument('--masking-mode', choices=['mask', 'token'], default='mask', help='Mask (human-readable mask) or token (HMAC)')
    parser.add_argument('--hmac-key', default=None, help='HMAC key for tokenization / audit fingerprints (optional; provide to enable deterministic tokens)')
    args = parser.parse_args()

    if args.masking_mode == 'token' and not args.hmac_key:
        print("WARNING: token mode recommended with --hmac-key to make tokens deterministic and auditable.")

    process_csv(
        input_path=args.input,
        output_path=args.output,
        report_path=args.report,
        chunksize=args.chunksize,
        masking_mode=args.masking_mode,
        hmac_key=args.hmac_key
    )

if __name__ == '__main__':
    main()

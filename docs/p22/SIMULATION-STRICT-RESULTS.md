# SIMULATION-STRICT-RESULTS — v1.2.2-HF1

FIELD_READY: **false**

```json
{
  "version": "1.2.2-HF1",
  "diagnostic": {
    "total": 48,
    "counts": {
      "PASS": 21,
      "BLOCKED": 27
    }
  },
  "office5pc": {
    "total": 12,
    "counts": {
      "PASS": 8,
      "BLOCKED": 4
    },
    "scenarios": [
      {
        "id": "OFFICE-01",
        "expected": "SERVER_PHYSICAL_LINK",
        "actual": "SERVER_PHYSICAL_LINK",
        "evidence": "findings=CMP-000,CMP-001; serverIssues=SERVER_PHYSICAL_LINK: server adapter reported down|All clients fail ICMP and TCP to server \u2014 likely server-side, L2 path, or infrastructure isolation.; insufficient=PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-02",
        "expected": "SERVER_POWER",
        "actual": "BLOCKED:NO_POWER_STATE_MODEL",
        "evidence": "findings=CMP-001; serverIssues=All clients fail ICMP and TCP to server \u2014 likely server-side, L2 path, or infrastructure isolation.; insufficient=PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis; power_token=SLEEP",
        "verdict": "BLOCKED"
      },
      {
        "id": "OFFICE-03",
        "expected": "POSSIBLE_IP_CONFLICT_NEEDS_CORROBORATION",
        "actual": "POSSIBLE_IP_CONFLICT_NEEDS_CORROBORATION",
        "evidence": "findings=CMP-001,CMP-003; serverIssues=All clients fail ICMP and TCP to server \u2014 likely server-side, L2 path, or infrastructure isolation.; insufficient=PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-04",
        "expected": "UPSTREAM_NETWORK_PATH",
        "actual": "BLOCKED:NO_PACKET_ARRIVAL_MODEL",
        "evidence": "findings=CMP-001; serverIssues=All clients fail ICMP and TCP to server \u2014 likely server-side, L2 path, or infrastructure isolation.; insufficient=PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis; received_probe=NO",
        "verdict": "BLOCKED"
      },
      {
        "id": "OFFICE-05",
        "expected": "HOST_REACHABLE_ICMP_SEPARATE",
        "actual": "HOST_REACHABLE_ICMP_SEPARATE",
        "evidence": "findings=CMP-004; insufficient=Insufficient TCP probes targeting server IP for common-outage analysis.|PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-06",
        "expected": "SERVER_WFP_FIREWALL_CONFIRMED",
        "actual": "BLOCKED:NO_WFP_MODEL",
        "evidence": "findings=CMP-001; serverIssues=All clients fail ICMP and TCP to server \u2014 likely server-side, L2 path, or infrastructure isolation.; insufficient=PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis; wfp_drop=YES",
        "verdict": "BLOCKED"
      },
      {
        "id": "OFFICE-07",
        "expected": "NEED_PACKET_PATH_OR_FIREWALL_EVIDENCE",
        "actual": "NEED_PACKET_PATH_OR_FIREWALL_EVIDENCE",
        "evidence": "findings=CMP-001; serverIssues=All clients fail ICMP and TCP to server \u2014 likely server-side, L2 path, or infrastructure isolation.; insufficient=PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-08",
        "expected": "CLIENT_SPECIFIC_FAULT",
        "actual": "CLIENT_SPECIFIC_FAULT",
        "evidence": "findings=CMP-005; clientIssues=CLIENT_SPECIFIC_FAULT: mixed reachability across clients to the same server; insufficient=Insufficient ICMP probes targeting server IP for common-outage analysis.|PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-09",
        "expected": "PRINT_RPC_APPLICATION_LAYER",
        "actual": "BLOCKED:NO_PRINTER_RPC_MODEL",
        "evidence": "findings=; insufficient=Insufficient ICMP probes targeting server IP for common-outage analysis.|Insufficient TCP probes targeting server IP for common-outage analysis.|PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "BLOCKED"
      },
      {
        "id": "OFFICE-10",
        "expected": "SHAPRINT_STARTUP_RECURRENCE",
        "actual": "SHAPRINT_STARTUP_RECURRENCE",
        "evidence": "findings=; insufficient=Insufficient ICMP probes targeting server IP for common-outage analysis.|Insufficient TCP probes targeting server IP for common-outage analysis.|PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis; sha=STOPPED tcp445=PASS tcp48631=FAIL",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-11",
        "expected": "INVALID_OR_INCONSISTENT_REPORTS",
        "actual": "INVALID_OR_INCONSISTENT_REPORTS",
        "evidence": "findings=; insufficient=PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis|INVALID_OR_INCONSISTENT_REPORTS: clients target different hosts \u2014 192.168.10.50,192.168.10.60",
        "verdict": "PASS"
      },
      {
        "id": "OFFICE-12",
        "expected": "INSUFFICIENT_EVIDENCE",
        "actual": "INSUFFICIENT_EVIDENCE",
        "evidence": "findings=; insufficient=Insufficient ICMP probes targeting server IP for common-outage analysis.|Insufficient TCP probes targeting server IP for common-outage analysis.|PC1: insufficient MAC evidence for conflict analysis|PC2: insufficient MAC evidence for conflict analysis|PC3: insufficient MAC evidence for conflict analysis|PC4: insufficient MAC evidence for conflict analysis",
        "verdict": "PASS"
      }
    ]
  },
  "faultInjection": {
    "total": 28,
    "pass": 28,
    "fail": 0,
    "executorProvenancePass": 28,
    "claim_28_of_28_real_executor": true,
    "fixtureSha256": "09d79218ac06a9d8cb7890f53a9488f54a888227294fe083858dbff9fad1f216"
  },
  "FIELD_READY": false,
  "notes": "HF1 strict simulation \u2014 no false PASS from any-finding or expected leakage. FIELD_READY false until physical Win10/11 validation."
}
```

## Office 5PC (exact)

| ID | Expected | Actual | Verdict |
|----|----------|--------|---------|
| OFFICE-01 | SERVER_PHYSICAL_LINK | SERVER_PHYSICAL_LINK | PASS |
| OFFICE-02 | SERVER_POWER | BLOCKED:NO_POWER_STATE_MODEL | BLOCKED |
| OFFICE-03 | POSSIBLE_IP_CONFLICT_NEEDS_CORROBORATION | POSSIBLE_IP_CONFLICT_NEEDS_CORROBORATION | PASS |
| OFFICE-04 | UPSTREAM_NETWORK_PATH | BLOCKED:NO_PACKET_ARRIVAL_MODEL | BLOCKED |
| OFFICE-05 | HOST_REACHABLE_ICMP_SEPARATE | HOST_REACHABLE_ICMP_SEPARATE | PASS |
| OFFICE-06 | SERVER_WFP_FIREWALL_CONFIRMED | BLOCKED:NO_WFP_MODEL | BLOCKED |
| OFFICE-07 | NEED_PACKET_PATH_OR_FIREWALL_EVIDENCE | NEED_PACKET_PATH_OR_FIREWALL_EVIDENCE | PASS |
| OFFICE-08 | CLIENT_SPECIFIC_FAULT | CLIENT_SPECIFIC_FAULT | PASS |
| OFFICE-09 | PRINT_RPC_APPLICATION_LAYER | BLOCKED:NO_PRINTER_RPC_MODEL | BLOCKED |
| OFFICE-10 | SHAPRINT_STARTUP_RECURRENCE | SHAPRINT_STARTUP_RECURRENCE | PASS |
| OFFICE-11 | INVALID_OR_INCONSISTENT_REPORTS | INVALID_OR_INCONSISTENT_REPORTS | PASS |
| OFFICE-12 | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE | PASS |

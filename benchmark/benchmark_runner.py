import os
import sys
import json
import asyncio
from pathlib import Path

# Add backend to sys.path so app modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from app.scanners.scanner_manager import ScannerManager
from app.analysis.correlation import FindingCorrelator
from app.analysis.risk_engine import RiskEngine

async def run_benchmark():
    benchmark_dir = ROOT_DIR / "benchmark"
    contracts_dir = benchmark_dir / "contracts"
    expected_path = benchmark_dir / "expected_findings" / "benchmark_ground_truth.json"
    results_dir = benchmark_dir / "results"
    results_dir.mkdir(exist_ok=True)

    with open(expected_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    scanner_manager = ScannerManager()

    tp = 0 # Vulnerable and detected as vulnerable
    fp = 0 # Secure but detected as vulnerable
    tn = 0 # Secure and detected as secure
    fn = 0 # Vulnerable but missed (detected as secure)

    detailed_eval = []

    print(f"\n==================================================================")
    print(f"      SECURECHAIN AUDITOR BENCHMARK EVALUATION (60 CONTRACTS)     ")
    print(f"==================================================================")

    for name, meta in ground_truth.items():
        sol_file = contracts_dir / meta["filename"]
        if not sol_file.exists():
            continue

        with open(sol_file, "r", encoding="utf-8") as f:
            source_code = f.read()

        raw_findings, fuzz_meta = await scanner_manager.run_scanners(
            file_path=str(sol_file),
            source_code=source_code,
            enabled_engines=["custom", "slither", "foundry"]
        )

        consolidated = FindingCorrelator.correlate(raw_findings)
        risk_score, risk_level, counts = RiskEngine.calculate_risk(consolidated, fuzz_meta)

        # A contract is considered vulnerable if high-severity issues or failed fuzz invariants are present
        detected_vulnerable = risk_level in ["CRITICAL", "HIGH", "MEDIUM"]
        expected_vulnerable = meta["has_vulnerability"]

        classification = ""
        if expected_vulnerable and detected_vulnerable:
            tp += 1
            classification = "TRUE_POSITIVE"
        elif not expected_vulnerable and not detected_vulnerable:
            tn += 1
            classification = "TRUE_NEGATIVE"
        elif not expected_vulnerable and detected_vulnerable:
            fp += 1
            classification = "FALSE_POSITIVE"
        elif expected_vulnerable and not detected_vulnerable:
            fn += 1
            classification = "FALSE_NEGATIVE"

        detailed_eval.append({
            "contract": name,
            "category": meta["category"],
            "expected_vulnerable": expected_vulnerable,
            "detected_vulnerable": detected_vulnerable,
            "classification": classification,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "findings_count": len(consolidated)
        })

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    benchmark_summary = {
        "total_contracts": total,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "metrics": {
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1_score * 100, 2)
        },
        "contracts_evaluated": detailed_eval
    }

    report_path = results_dir / "benchmark_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_summary, f, indent=2)

    print(f"\nBenchmark Evaluation Complete:")
    print(f"Total Contracts Tested : {total}")
    print(f"True Positives (TP)    : {tp}")
    print(f"True Negatives (TN)    : {tn}")
    print(f"False Positives (FP)   : {fp}")
    print(f"False Negatives (FN)   : {fn}")
    print(f"------------------------------------------------------------------")
    print(f"Detection Accuracy     : {accuracy * 100:.1f}%")
    print(f"Precision              : {precision * 100:.1f}%")
    print(f"Recall (Sensitivity)   : {recall * 100:.1f}%")
    print(f"F1-Score               : {f1_score * 100:.1f}%")
    print(f"------------------------------------------------------------------")
    print(f"Full benchmark artifact saved to: {report_path}\n")

if __name__ == "__main__":
    asyncio.run(run_benchmark())

import os
import sys
import json
import asyncio
from pathlib import Path
from collections import defaultdict

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

    # Overall contract-level counters
    tp = 0 # Vulnerable and detected as vulnerable
    fp = 0 # Secure but detected as vulnerable
    tn = 0 # Secure and detected as secure
    fn = 0 # Vulnerable but missed (detected as secure)

    # Category-level counters: {category: {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}}
    categories = ["REENTRANCY", "ACCESS_CONTROL", "UNCHECKED_CALL", "ORACLE_MANIPULATION", "SECURE_BASELINE"]
    category_metrics = {cat: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for cat in categories}

    # Dataset partition counters: 'synthetic_template' vs 'independent'
    datasets = {
        "synthetic_template": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "independent": {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    }

    detailed_eval = []

    print("\n" + "=" * 76)
    print(f"   SECURECHAIN AUDITOR BENCHMARK EVALUATION ({len(ground_truth)} CONTRACTS)")
    print("=" * 76)

    for name, meta in ground_truth.items():
        sol_file = contracts_dir / meta["filename"]
        if not sol_file.exists():
            print(f"[WARN] Contract file not found: {sol_file}")
            continue

        with open(sol_file, "r", encoding="utf-8") as f:
            source_code = f.read()

        # Strict separation: Scanners receive ONLY file path and source code
        raw_findings, fuzz_meta = await scanner_manager.run_scanners(
            file_path=str(sol_file),
            source_code=source_code,
            enabled_engines=["custom", "slither", "foundry"]
        )

        consolidated = FindingCorrelator.correlate(raw_findings)
        risk_score, risk_level, counts = RiskEngine.calculate_risk(consolidated, fuzz_meta)

        # A contract is considered vulnerable if high/critical/medium risk issues or failed fuzz invariants are present
        detected_vulnerable = risk_level in ["CRITICAL", "HIGH", "MEDIUM"]
        expected_vulnerable = meta["has_vulnerability"]
        target_category = meta.get("category", "OTHER")
        dataset_key = "independent" if "independent" in meta.get("dataset_type", "") else "synthetic_template"

        # Contract-level classification
        if expected_vulnerable and detected_vulnerable:
            tp += 1
            classification = "TRUE_POSITIVE"
            datasets[dataset_key]["tp"] += 1
        elif not expected_vulnerable and not detected_vulnerable:
            tn += 1
            classification = "TRUE_NEGATIVE"
            datasets[dataset_key]["tn"] += 1
        elif not expected_vulnerable and detected_vulnerable:
            fp += 1
            classification = "FALSE_POSITIVE"
            datasets[dataset_key]["fp"] += 1
        elif expected_vulnerable and not detected_vulnerable:
            fn += 1
            classification = "FALSE_NEGATIVE"
            datasets[dataset_key]["fn"] += 1

        # Check detected categories among findings
        detected_categories = {f["category"] for f in consolidated if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]}
        category_match = target_category in detected_categories if expected_vulnerable else len(detected_categories) == 0

        # Update category-level breakdown
        cat_key = target_category if target_category in category_metrics else "SECURE_BASELINE"
        if expected_vulnerable:
            if target_category in detected_categories:
                category_metrics[cat_key]["tp"] += 1
            else:
                category_metrics[cat_key]["fn"] += 1
        else:
            if detected_vulnerable:
                category_metrics[cat_key]["fp"] += 1
            else:
                category_metrics[cat_key]["tn"] += 1

        detailed_eval.append({
            "contract": name,
            "filename": meta["filename"],
            "dataset_type": meta.get("dataset_type", "synthetic_template"),
            "category": target_category,
            "expected_vulnerable": expected_vulnerable,
            "detected_vulnerable": detected_vulnerable,
            "category_match": category_match,
            "detected_categories": list(detected_categories),
            "classification": classification,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "findings_count": len(consolidated)
        })

    def calc_stats(tp_c, tn_c, fp_c, fn_c):
        tot = tp_c + tn_c + fp_c + fn_c
        acc = (tp_c + tn_c) / tot if tot > 0 else 0.0
        prec = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
        rec = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        return {
            "total": tot,
            "tp": tp_c,
            "tn": tn_c,
            "fp": fp_c,
            "fn": fn_c,
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2)
        }

    overall_stats = calc_stats(tp, tn, fp, fn)
    synthetic_stats = calc_stats(datasets["synthetic_template"]["tp"], datasets["synthetic_template"]["tn"], datasets["synthetic_template"]["fp"], datasets["synthetic_template"]["fn"])
    independent_stats = calc_stats(datasets["independent"]["tp"], datasets["independent"]["tn"], datasets["independent"]["fp"], datasets["independent"]["fn"])

    category_stats = {}
    for cat, counts in category_metrics.items():
        category_stats[cat] = calc_stats(counts["tp"], counts["tn"], counts["fp"], counts["fn"])

    benchmark_summary = {
        "overall_evaluation": overall_stats,
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn
        },
        "dataset_breakdown": {
            "synthetic_template": synthetic_stats,
            "independent_public": independent_stats
        },
        "category_breakdown": category_stats,
        "contracts_evaluated": detailed_eval
    }

    report_path = results_dir / "benchmark_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_summary, f, indent=2)

    print("\n" + "=" * 76)
    print("                    OVERALL BENCHMARK RESULTS")
    print("=" * 76)
    print(f"Total Contracts Tested : {overall_stats['total']}")
    print(f"True Positives (TP)    : {tp}")
    print(f"True Negatives (TN)    : {tn}")
    print(f"False Positives (FP)   : {fp}")
    print(f"False Negatives (FN)   : {fn}")
    print("-" * 76)
    print(f"Overall Accuracy       : {overall_stats['accuracy']}%")
    print(f"Precision              : {overall_stats['precision']}%")
    print(f"Recall (Sensitivity)   : {overall_stats['recall']}%")
    print(f"F1-Score               : {overall_stats['f1_score']}%")
    print("-" * 76)
    print(f"Synthetic Template Set : Acc {synthetic_stats['accuracy']}%, F1 {synthetic_stats['f1_score']}% (N={synthetic_stats['total']})")
    print(f"Independent Public Set : Acc {independent_stats['accuracy']}%, F1 {independent_stats['f1_score']}% (N={independent_stats['total']})")
    print("-" * 76)
    print("CATEGORY BREAKDOWN:")
    for cat, c_stat in category_stats.items():
        print(f"  - {cat:<22}: TP={c_stat['tp']}, TN={c_stat['tn']}, FP={c_stat['fp']}, FN={c_stat['fn']} | Prec={c_stat['precision']}%, Rec={c_stat['recall']}%, F1={c_stat['f1_score']}%")
    print("=" * 76)
    print(f"Full benchmark artifact saved to: {report_path}\n")

if __name__ == "__main__":
    asyncio.run(run_benchmark())

"""Compare reconstructed incidents with a dataset's ground truth (real numbers only)."""


def evaluate(incidents, ground_truth):
    truth = {ref for refs in ground_truth.get("attack_events", {}).values() for ref in refs}
    found = {ref for inc in incidents for ref in inc.chain["raw_ref"]}
    hits = truth & found
    return {
        "ground_truth_events": len(truth),
        "reconstructed_events": len(found),
        "correctly_linked": len(hits),
        "recall": len(hits) / len(truth) if truth else None,
        "precision": len(hits) / len(found) if found else None,
        "missed": sorted(truth - found),
        "false_positives": sorted(found - truth),
    }

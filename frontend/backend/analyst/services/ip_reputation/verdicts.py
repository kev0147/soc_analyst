from analyst.models.choices import ReputationVerdict


VERDICT_WEIGHT = {
    ReputationVerdict.MALICIOUS: 3,
    ReputationVerdict.SUSPICIOUS: 2,
    ReputationVerdict.CLEAN: 1,
    ReputationVerdict.UNKNOWN: 0,
}


def verdict_from_score(score: float | None) -> str:
    if score is None:
        return ReputationVerdict.UNKNOWN
    if score >= 70:
        return ReputationVerdict.MALICIOUS
    if score >= 25:
        return ReputationVerdict.SUSPICIOUS
    return ReputationVerdict.CLEAN


def aggregate_verdict(results) -> str:
    verdict = ReputationVerdict.UNKNOWN
    for result in results:
        if VERDICT_WEIGHT[result.verdict] > VERDICT_WEIGHT[verdict]:
            verdict = result.verdict
    return verdict

/**
 * Hybrid Decision Engine
 * Orchestrates Supervised Random Forest + Unsupervised Isolation Forest.
 */

import { AttackCategory, HybridDetectionResult, NetworkFlow } from '../types/nids';
import { evaluateSupervised } from './randomForest';
import { evaluateIsolationForest } from './isolationForest';

export interface EngineConfig {
  isolationThreshold: number; // default ~0.62
  rfConfidenceCutoff: number; // default ~0.65
}

export const DEFAULT_CONFIG: EngineConfig = {
  isolationThreshold: 0.62,
  rfConfidenceCutoff: 0.65,
};

export function analyzeFlow(
  flow: NetworkFlow,
  config: EngineConfig = DEFAULT_CONFIG
): HybridDetectionResult {
  const startTime = performance.now();

  const supervised = evaluateSupervised(flow);
  const outlier = evaluateIsolationForest(flow, config.isolationThreshold);

  let finalVerdict: AttackCategory = 'Benign';
  let isThreat = false;
  let severity: HybridDetectionResult['severity'] = 'benign';
  let explanation = '';

  const isSupervisedAttack =
    supervised.predictedClass !== 'Benign' &&
    supervised.confidence >= config.rfConfidenceCutoff;

  if (isSupervisedAttack) {
    // Known Signature / Pattern Match via Random Forest
    finalVerdict = supervised.predictedClass;
    isThreat = true;

    if (finalVerdict === 'DDoS' || finalVerdict === 'Infiltration') {
      severity = 'critical';
    } else if (finalVerdict === 'BruteForce' || finalVerdict === 'WebAttack') {
      severity = 'high';
    } else {
      severity = 'medium';
    }

    if (outlier.isOutlier) {
      explanation = `Dual-Engine Confirmation: Supervised model matched ${finalVerdict} signature (${(supervised.confidence * 100).toFixed(1)}% conf) and Isolation Forest flagged statistical divergence (Score: ${outlier.anomalyScore}).`;
    } else {
      explanation = `Signature Detection: Random Forest ensemble classified as ${finalVerdict} based on rule: ${supervised.ruleMatched}.`;
    }
  } else if (outlier.isOutlier) {
    // Zero-Day Anomaly Detection: Supervised saw no known signature, but statistical distribution is highly anomalous
    finalVerdict = 'ZeroDay';
    isThreat = true;
    severity = outlier.anomalyScore > 0.85 ? 'critical' : 'high';

    const topDeviations = outlier.contributingFeatures
      .slice(0, 2)
      .map((f) => `${f.featureName} (z=${f.deviationZScore})`)
      .join(', ');

    explanation = `Zero-Day Anomaly: Bypassed known signatures (classified benign by RF), but Isolation Forest detected severe statistical divergence (Score: ${outlier.anomalyScore}). Outlier features: ${topDeviations || 'multivariate variance'}.`;
  } else {
    // Flow is Benign according to both engines
    finalVerdict = 'Benign';
    isThreat = false;
    severity = 'benign';
    explanation = `Nominal Flow: Conforms to standard protocol profiles. Supervised benign confidence: ${(supervised.confidence * 100).toFixed(1)}%, Isolation score: ${outlier.anomalyScore}.`;
  }

  const processedAt = performance.now() - startTime;

  return {
    flow,
    supervised,
    outlier,
    finalVerdict,
    isThreat,
    severity,
    explanation,
    processedAt: Number(processedAt.toFixed(3)),
  };
}

/**
 * Unsupervised Outlier Scoring Engine (simulating an Isolation Forest)
 * Designed for Zero-Day & Unknown Anomaly Detection.
 * 
 * Computes multidimensional feature deviations from benign baseline distributions
 * and approximates isolation tree path depth:
 * Anomaly Score s(x) = 2^(-E(h(x)) / c(n))
 */

import { NetworkFlow, OutlierVerdict } from '../types/nids';

// Baseline empirical statistics for standard enterprise benign network flows
interface FeatureBaseline {
  mean: number;
  std: number;
  weight: number;
}

const BENIGN_BASELINES: Record<string, FeatureBaseline> = {
  flowPacketsPerSec: { mean: 45.2, std: 110.5, weight: 1.5 },
  flowBytesPerSec: { mean: 12500, std: 45000, weight: 1.2 },
  flowDurationMs: { mean: 350.0, std: 800.0, weight: 1.0 },
  fwdPacketLengthMean: { mean: 280.0, std: 320.0, weight: 1.1 },
  bwdPacketLengthMean: { mean: 510.0, std: 480.0, weight: 1.1 },
  flowIATMeanMs: { mean: 48.0, std: 95.0, weight: 1.2 },
  totalFwdPackets: { mean: 6.5, std: 14.0, weight: 0.9 },
};

export function evaluateIsolationForest(
  flow: NetworkFlow,
  outlierSensitivityThreshold: number = 0.62
): OutlierVerdict {
  const contributingFeatures: OutlierVerdict['contributingFeatures'] = [];
  let weightedZScoreSum = 0;
  let totalWeight = 0;

  // 1. Evaluate numerical feature deviations (Z-score analysis)
  for (const [feat, baseline] of Object.entries(BENIGN_BASELINES)) {
    const val = (flow as unknown as Record<string, number>)[feat] ?? 0;
    // Cap standard score calculation to avoid single feature blowout
    const rawZ = Math.abs(val - baseline.mean) / Math.max(1, baseline.std);
    const zScore = Math.min(rawZ, 12);

    weightedZScoreSum += zScore * baseline.weight;
    totalWeight += baseline.weight;

    if (zScore > 2.5) {
      contributingFeatures.push({
        featureName: feat,
        deviationZScore: Number(zScore.toFixed(2)),
        weight: baseline.weight,
      });
    }
  }

  // 2. Evaluate flag combination anomalies (unusual TCP flag states that trees isolate early)
  let flagPenalty = 0;
  // SYN + FIN simultaneously is RFC invalid (Xmas scan / custom stack fuzzing)
  if (flow.flagSyn === 1 && flow.flagFin === 1) {
    flagPenalty += 3.5;
    contributingFeatures.push({
      featureName: 'SYN+FIN Flag Conflict (RFC Invariant Breach)',
      deviationZScore: 5.0,
      weight: 2.0,
    });
  }
  // Zero flags set in TCP flow
  if (flow.protocol === 'TCP' && flow.flagSyn === 0 && flow.flagAck === 0 && flow.flagFin === 0 && flow.flagRst === 0 && flow.flagPsh === 0) {
    flagPenalty += 2.8;
    contributingFeatures.push({
      featureName: 'Zero TCP Flags (NULL State)',
      deviationZScore: 4.2,
      weight: 1.8,
    });
  }

  // 3. Approximate Isolation Forest Path Length:
  // In an Isolation Forest, anomalous points are isolated in very few splits (short path length).
  // E(h(x)) decreases as anomaly increases.
  const averageZ = (weightedZScoreSum + flagPenalty * 2) / totalWeight;
  
  // Transform z-score into non-linear isolation anomaly score [0.0 - 1.0]
  // Using sigmoid / exponential path length transformation
  const rawScore = 1 / (1 + Math.exp(-0.85 * (averageZ - 2.8)));
  const anomalyScore = Math.min(0.99, Math.max(0.01, Number(rawScore.toFixed(3))));

  // Sort contributing features by severity
  contributingFeatures.sort((a, b) => b.deviationZScore - a.deviationZScore);

  const isOutlier = anomalyScore >= outlierSensitivityThreshold;

  return {
    anomalyScore,
    isOutlier,
    contributingFeatures,
  };
}

/**
 * Types for Hybrid NIDS (Network Intrusion Detection System)
 * Compatible with CIC-IDS benchmark feature schema.
 */

export type AttackCategory =
  | 'Benign'
  | 'DDoS'
  | 'PortScan'
  | 'BruteForce'
  | 'WebAttack'
  | 'Botnet'
  | 'Infiltration'
  | 'ZeroDay';

export type ProtocolType = 'TCP' | 'UDP' | 'ICMP';

export interface NetworkFlow {
  id: string;
  timestamp: number;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: ProtocolType;
  
  // Numerical flow metrics (CIC-IDS standard features)
  flowDurationMs: number;
  totalFwdPackets: number;
  totalBwdPackets: number;
  flowBytesPerSec: number;
  flowPacketsPerSec: number;
  fwdPacketLengthMean: number;
  bwdPacketLengthMean: number;
  flowIATMeanMs: number; // Inter-Arrival Time mean
  
  // TCP Flags
  flagSyn: number; // 0 or 1
  flagAck: number;
  flagFin: number;
  flagRst: number;
  flagPsh: number;
  
  // Optional ground truth label from dataset
  groundTruthLabel?: string;
}

export interface SupervisedVerdict {
  predictedClass: AttackCategory;
  confidence: number; // 0.0 - 1.0
  ruleMatched: string;
  decisionPath: string[];
}

export interface OutlierVerdict {
  anomalyScore: number; // 0.0 - 1.0 (> 0.60 indicates anomaly)
  isOutlier: boolean;
  contributingFeatures: {
    featureName: string;
    deviationZScore: number;
    weight: number;
  }[];
}

export interface HybridDetectionResult {
  flow: NetworkFlow;
  supervised: SupervisedVerdict;
  outlier: OutlierVerdict;
  finalVerdict: AttackCategory;
  isThreat: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'benign';
  explanation: string;
  processedAt: number;
}

export interface SOCMetrics {
  totalFlows: number;
  anomaliesDetected: number;
  normalFlows: number;
  threatsByType: Record<AttackCategory, number>;
  throughputBps: number;
  currentFlowRate: number; // flows/sec
  averageInferenceLatencyMs: number;
  systemHealth: 'nominal' | 'degraded' | 'alert';
  accuracyRate: number; // evaluated against ground truth if present
  falsePositiveRate: number;
  totalEvaluatedWithGroundTruth: number;
}

export interface ConfusionMatrix {
  truePositives: number;
  trueNegatives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
}

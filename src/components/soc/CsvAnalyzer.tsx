import React, { useState } from 'react';
import Papa from 'papaparse';
import {
  UploadCloud,
  FileText,
  CheckCircle2,
  AlertCircle,
  Download,
  Database,
  BarChart3,
  RefreshCw,
} from 'lucide-react';
import {
  NetworkFlow,
  HybridDetectionResult,
  ConfusionMatrix,
  ProtocolType,
} from '../../types/nids';
import { analyzeFlow } from '../../engine/hybridEngine';
import { SAMPLE_DATASETS } from '../../data/sampleDatasets';

interface CsvAnalyzerProps {
  onLoadDatasetToSOC: (results: HybridDetectionResult[]) => void;
}

export const CsvAnalyzer: React.FC<CsvAnalyzerProps> = ({ onLoadDatasetToSOC }) => {
  const [isProcessing, setIsProcessing] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [results, setResults] = useState<HybridDetectionResult[]>([]);
  const [confusionMatrix, setConfusionMatrix] = useState<ConfusionMatrix | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Helper to extract numeric field flexibly from CIC-IDS or generic CSV headers
  const getNum = (row: Record<string, unknown>, candidateKeys: string[], defaultVal = 0): number => {
    for (const key of candidateKeys) {
      // Check direct match or case-insensitive / trimmed match
      for (const rowKey of Object.keys(row)) {
        if (rowKey.trim().toLowerCase() === key.toLowerCase()) {
          const val = parseFloat(String(row[rowKey]));
          if (!isNaN(val) && isFinite(val)) return val;
        }
      }
    }
    return defaultVal;
  };

  const getString = (row: Record<string, unknown>, candidateKeys: string[], defaultVal = ''): string => {
    for (const key of candidateKeys) {
      for (const rowKey of Object.keys(row)) {
        if (rowKey.trim().toLowerCase() === key.toLowerCase()) {
          const val = String(row[rowKey]).trim();
          if (val) return val;
        }
      }
    }
    return defaultVal;
  };

  const processParsedRows = (rows: Record<string, unknown>[], sourceName: string) => {
    setIsProcessing(true);
    setErrorMsg(null);

    try {
      const processed: HybridDetectionResult[] = [];
      let tp = 0;
      let tn = 0;
      let fp = 0;
      let fn = 0;
      let hasGroundTruth = false;

      rows.forEach((row, idx) => {
        // Extract flow attributes matching CIC-IDS schema
        const duration = getNum(row, ['flow duration', 'flow_duration', 'duration', 'Flow.Duration'], 100);
        const fwdPkts = getNum(row, ['total fwd packets', 'total_fwd_packets', 'fwd packets', 'Total.Fwd.Packets'], 4);
        const bwdPkts = getNum(row, ['total backward packets', 'total_bwd_packets', 'bwd packets', 'Total.Bwd.Packets'], 3);
        const bytesSec = getNum(row, ['flow bytes/s', 'flow_bytes_s', 'flow.bytes.s', 'bytes/s'], 15000);
        const pktsSec = getNum(row, ['flow packets/s', 'flow_packets_s', 'flow.packets.s', 'packets/s'], 30);
        const fwdLenMean = getNum(row, ['fwd packet length mean', 'fwd_packet_length_mean', 'Fwd.Packet.Length.Mean'], 250);
        const bwdLenMean = getNum(row, ['bwd packet length mean', 'bwd_packet_length_mean', 'Bwd.Packet.Length.Mean'], 400);
        const iatMean = getNum(row, ['flow iat mean', 'flow_iat_mean', 'Flow.IAT.Mean', 'iat mean'], 35);

        const syn = getNum(row, ['syn flag count', 'syn_flag_count', 'flag_syn', 'SYN.Flag.Count'], 1);
        const ack = getNum(row, ['ack flag count', 'ack_flag_count', 'flag_ack', 'ACK.Flag.Count'], 1);
        const fin = getNum(row, ['fin flag count', 'fin_flag_count', 'flag_fin', 'FIN.Flag.Count'], 0);
        const rst = getNum(row, ['rst flag count', 'rst_flag_count', 'flag_rst', 'RST.Flag.Count'], 0);
        const psh = getNum(row, ['psh flag count', 'psh_flag_count', 'flag_psh', 'PSH.Flag.Count'], 0);

        const destPort = getNum(row, ['destination port', 'dest_port', 'dst_port', 'port', 'Destination.Port'], 443);
        const srcPort = getNum(row, ['source port', 'src_port', 'Source.Port'], 50000 + (idx % 10000));
        const protoStr = getString(row, ['protocol', 'proto', 'Protocol'], 'TCP').toUpperCase();
        const protocol: ProtocolType = protoStr.includes('UDP') ? 'UDP' : protoStr.includes('ICMP') ? 'ICMP' : 'TCP';

        const label = getString(row, ['label', 'class', 'attack', 'Label']);

        const flow: NetworkFlow = {
          id: `csv_flow_${idx}_${Date.now()}`,
          timestamp: Date.now() - (rows.length - idx) * 150,
          sourceIp: getString(row, ['source ip', 'src_ip', 'Source.IP'], `192.168.1.${(idx % 250) + 2}`),
          sourcePort: Math.round(srcPort),
          destinationIp: getString(row, ['destination ip', 'dst_ip', 'Destination.IP'], '192.168.1.100'),
          destinationPort: Math.round(destPort),
          protocol,
          flowDurationMs: duration,
          totalFwdPackets: Math.round(fwdPkts),
          totalBwdPackets: Math.round(bwdPkts),
          flowBytesPerSec: bytesSec,
          flowPacketsPerSec: pktsSec,
          fwdPacketLengthMean: fwdLenMean,
          bwdPacketLengthMean: bwdLenMean,
          flowIATMeanMs: iatMean,
          flagSyn: syn > 0 ? 1 : 0,
          flagAck: ack > 0 ? 1 : 0,
          flagFin: fin > 0 ? 1 : 0,
          flagRst: rst > 0 ? 1 : 0,
          flagPsh: psh > 0 ? 1 : 0,
          groundTruthLabel: label || undefined,
        };

        const res = analyzeFlow(flow);
        processed.push(res);

        // Ground-truth evaluation if label exists
        if (label) {
          hasGroundTruth = true;
          const isActualBenign = label.toUpperCase() === 'BENIGN' || label.toUpperCase() === 'NORMAL';
          const isPredictedThreat = res.isThreat;

          if (!isActualBenign && isPredictedThreat) tp++;
          else if (isActualBenign && !isPredictedThreat) tn++;
          else if (isActualBenign && isPredictedThreat) fp++;
          else if (!isActualBenign && !isPredictedThreat) fn++;
        }
      });

      setResults(processed);
      setFileName(sourceName);

      if (hasGroundTruth && tp + tn + fp + fn > 0) {
        const accuracy = (tp + tn) / (tp + tn + fp + fn);
        const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
        const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
        const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

        setConfusionMatrix({
          truePositives: tp,
          trueNegatives: tn,
          falsePositives: fp,
          falseNegatives: fn,
          accuracy,
          precision,
          recall,
          f1Score,
        });
      } else {
        setConfusionMatrix(null);
      }
    } catch (err) {
      setErrorMsg(`Error evaluating CSV: ${(err as Error).message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsProcessing(true);
    Papa.parse(file, {
      header: true,
      dynamicTyping: true,
      skipEmptyLines: true,
      complete: (parseResult) => {
        if (parseResult.data && parseResult.data.length > 0) {
          processParsedRows(parseResult.data as Record<string, unknown>[], file.name);
        } else {
          setErrorMsg('CSV file appeared empty or could not be parsed.');
          setIsProcessing(false);
        }
      },
      error: (err) => {
        setErrorMsg(`CSV Parsing failure: ${err.message}`);
        setIsProcessing(false);
      },
    });
  };

  const handleLoadPreset = (datasetId: string) => {
    const preset = SAMPLE_DATASETS.find((d) => d.id === datasetId);
    if (!preset) return;

    setIsProcessing(true);
    setTimeout(() => {
      const generatedFlows = preset.generate();
      const rows: Record<string, unknown>[] = generatedFlows.map((f) => ({
        'Flow Duration': f.flowDurationMs,
        'Total Fwd Packets': f.totalFwdPackets,
        'Total Backward Packets': f.totalBwdPackets,
        'Flow Bytes/s': f.flowBytesPerSec,
        'Flow Packets/s': f.flowPacketsPerSec,
        'Fwd Packet Length Mean': f.fwdPacketLengthMean,
        'Bwd Packet Length Mean': f.bwdPacketLengthMean,
        'Flow IAT Mean': f.flowIATMeanMs,
        'SYN Flag Count': f.flagSyn,
        'ACK Flag Count': f.flagAck,
        'FIN Flag Count': f.flagFin,
        'RST Flag Count': f.flagRst,
        'PSH Flag Count': f.flagPsh,
        'Destination Port': f.destinationPort,
        'Protocol': f.protocol,
        'Label': f.groundTruthLabel,
      }));
      processParsedRows(rows, `${preset.name} (${preset.flowCount} flows)`);
    }, 50);
  };

  const handleExportCSV = () => {
    if (results.length === 0) return;

    const exportRows = results.map((r) => ({
      Timestamp: new Date(r.flow.timestamp).toISOString(),
      Source_IP: r.flow.sourceIp,
      Source_Port: r.flow.sourcePort,
      Destination_IP: r.flow.destinationIp,
      Destination_Port: r.flow.destinationPort,
      Protocol: r.flow.protocol,
      Flow_Duration_ms: r.flow.flowDurationMs,
      Packets_Per_Sec: r.flow.flowPacketsPerSec,
      Bytes_Per_Sec: r.flow.flowBytesPerSec,
      RandomForest_Predicted: r.supervised.predictedClass,
      RandomForest_Confidence: r.supervised.confidence,
      Isolation_Anomaly_Score: r.outlier.anomalyScore,
      Is_Outlier: r.outlier.isOutlier,
      Final_Verdict: r.finalVerdict,
      Is_Threat: r.isThreat,
      Ground_Truth: r.flow.groundTruthLabel || 'N/A',
      Inference_Latency_ms: r.processedAt,
    }));

    const csvContent = Papa.unparse(exportRows);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `hybrid_nids_results_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="w-full space-y-6">
      {/* Top Banner & Upload Dropzone */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              Client-Side CSV Flow Ingestion & Benchmark Parser
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Supports standard CIC-IDS2017/2018 captures. Evaluates 100% locally in browser memory with zero server upload.
            </p>
          </div>
        </div>

        {/* Dropzone container */}
        <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-lg p-6 text-center transition-colors bg-slate-950/60">
          <input
            type="file"
            accept=".csv"
            id="csv-file-input"
            onChange={handleFileUpload}
            className="hidden"
          />
          <label
            htmlFor="csv-file-input"
            className="cursor-pointer flex flex-col items-center justify-center space-y-2"
          >
            <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center text-cyan-400">
              <FileText className="w-6 h-6" />
            </div>
            <div className="text-sm font-medium text-slate-200">
              Click to select a CIC-IDS CSV file or drag and drop
            </div>
            <div className="text-xs text-slate-500 font-mono">
              Accepted format: .csv with Flow Duration, Packets/s, Bytes/s, Flags, and optional Label
            </div>
          </label>
        </div>

        {/* Preloaded Datasets Shortcut */}
        <div className="mt-4 border-t border-slate-800/80 pt-3">
          <div className="flex items-center gap-2 mb-2 text-xs text-slate-400 font-mono">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>Or load benchmark dataset directly:</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {SAMPLE_DATASETS.map((ds) => (
              <button
                key={ds.id}
                onClick={() => handleLoadPreset(ds.id)}
                disabled={isProcessing}
                className="p-2.5 text-left bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-cyan-700/60 rounded transition-colors group"
              >
                <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 truncate">
                  {ds.name}
                </div>
                <div className="text-[11px] text-slate-500 mt-1 line-clamp-1">
                  {ds.description}
                </div>
              </button>
            ))}
          </div>
        </div>

        {errorMsg && (
          <div className="mt-4 p-3 bg-red-950/40 border border-red-900 rounded text-xs text-red-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Results View */}
      {results.length > 0 && (
        <div className="space-y-6">
          {/* Quick Action Bar */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <div>
                <span className="text-sm font-semibold text-slate-200">{fileName}</span>
                <span className="text-xs text-slate-400 font-mono ml-3 tabular-nums">
                  {results.length.toLocaleString()} flows analyzed
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => onLoadDatasetToSOC(results)}
                className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded transition-colors flex items-center gap-1.5 font-mono"
              >
                <BarChart3 className="w-3.5 h-3.5" />
                Transfer to Live SOC Dashboard
              </button>
              <button
                onClick={handleExportCSV}
                className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors flex items-center gap-1.5 font-mono"
              >
                <Download className="w-3.5 h-3.5" />
                Export Classified CSV
              </button>
            </div>
          </div>

          {/* Confusion Matrix / Accuracy Card if Ground Truth was present */}
          {confusionMatrix && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-1 flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                Ground Truth Validation & Confusion Matrix
              </h4>
              <p className="text-xs text-slate-500 mb-4 font-mono">
                Evaluated against the dataset's ground truth label column
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-[11px] text-slate-400 block font-mono">Accuracy</span>
                  <span className="text-xl font-bold font-mono text-emerald-400 tabular-nums">
                    {(confusionMatrix.accuracy * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-[11px] text-slate-400 block font-mono">Precision</span>
                  <span className="text-xl font-bold font-mono text-cyan-400 tabular-nums">
                    {(confusionMatrix.precision * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-[11px] text-slate-400 block font-mono">Recall (Detection)</span>
                  <span className="text-xl font-bold font-mono text-cyan-400 tabular-nums">
                    {(confusionMatrix.recall * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-[11px] text-slate-400 block font-mono">F1-Score</span>
                  <span className="text-xl font-bold font-mono text-slate-200 tabular-nums">
                    {confusionMatrix.f1Score.toFixed(3)}
                  </span>
                </div>
              </div>

              {/* 2x2 Matrix */}
              <div className="max-w-md mx-auto bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs">
                <div className="text-center text-slate-400 mb-3 text-[11px] uppercase tracking-wider">
                  Confusion Matrix Grid
                </div>
                <div className="grid grid-cols-2 gap-3 text-center">
                  <div className="p-3 bg-emerald-950/25 border border-emerald-900/40 rounded">
                    <span className="text-[10px] text-slate-400 block">True Positives (TP)</span>
                    <span className="text-lg font-bold text-emerald-400 tabular-nums">
                      {confusionMatrix.truePositives.toLocaleString()}
                    </span>
                    <span className="text-[10px] text-slate-500 block">Attacks Caught</span>
                  </div>
                  <div className="p-3 bg-red-950/25 border border-red-900/40 rounded">
                    <span className="text-[10px] text-slate-400 block">False Positives (FP)</span>
                    <span className="text-lg font-bold text-red-400 tabular-nums">
                      {confusionMatrix.falsePositives.toLocaleString()}
                    </span>
                    <span className="text-[10px] text-slate-500 block">Benign Flagged</span>
                  </div>
                  <div className="p-3 bg-amber-950/25 border border-amber-900/40 rounded">
                    <span className="text-[10px] text-slate-400 block">False Negatives (FN)</span>
                    <span className="text-lg font-bold text-amber-400 tabular-nums">
                      {confusionMatrix.falseNegatives.toLocaleString()}
                    </span>
                    <span className="text-[10px] text-slate-500 block">Missed Attacks</span>
                  </div>
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded">
                    <span className="text-[10px] text-slate-400 block">True Negatives (TN)</span>
                    <span className="text-lg font-bold text-slate-200 tabular-nums">
                      {confusionMatrix.trueNegatives.toLocaleString()}
                    </span>
                    <span className="text-[10px] text-slate-500 block">Normal Verified</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Sample classified rows */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center text-xs">
              <span className="font-semibold text-slate-200 font-mono">
                Classified Flow Stream (First 50 of {results.length.toLocaleString()})
              </span>
              <span className="text-slate-500 font-mono">Dual-Engine Classification Output</span>
            </div>

            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider sticky top-0">
                    <th className="py-2.5 px-3">Flow ID</th>
                    <th className="py-2.5 px-3">Endpoints</th>
                    <th className="py-2.5 px-2">Duration</th>
                    <th className="py-2.5 px-3 text-right">Packets/s</th>
                    <th className="py-2.5 px-3 text-right">RF Predicted</th>
                    <th className="py-2.5 px-3 text-right">Outlier Score</th>
                    <th className="py-2.5 px-3">Verdict</th>
                    <th className="py-2.5 px-3">Ground Truth</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {results.slice(0, 50).map((r) => (
                    <tr
                      key={r.flow.id}
                      className={
                        r.finalVerdict === 'ZeroDay'
                          ? 'bg-cyan-950/20'
                          : r.isThreat
                          ? 'bg-red-950/20'
                          : 'hover:bg-slate-800/40'
                      }
                    >
                      <td className="py-2 px-3 text-slate-400 truncate max-w-[120px]">
                        {r.flow.id}
                      </td>
                      <td className="py-2 px-3 text-slate-300 whitespace-nowrap">
                        {r.flow.sourceIp} → {r.flow.destinationPort}/{r.flow.protocol}
                      </td>
                      <td className="py-2 px-2 text-slate-400 tabular-nums">
                        {r.flow.flowDurationMs.toFixed(0)}ms
                      </td>
                      <td className="py-2 px-3 text-right text-slate-300 tabular-nums">
                        {Math.round(r.flow.flowPacketsPerSec).toLocaleString()}
                      </td>
                      <td className="py-2 px-3 text-right text-slate-300 tabular-nums">
                        {r.supervised.predictedClass} ({(r.supervised.confidence * 100).toFixed(0)}%)
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums">
                        <span className={r.outlier.anomalyScore > 0.62 ? 'text-cyan-400 font-bold' : 'text-slate-400'}>
                          {r.outlier.anomalyScore.toFixed(3)}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {r.finalVerdict === 'ZeroDay' ? (
                          <span className="text-cyan-400 font-medium">Zero-Day</span>
                        ) : r.isThreat ? (
                          <span className="text-red-400 font-medium">{r.finalVerdict}</span>
                        ) : (
                          <span className="text-emerald-400 font-medium">Benign</span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                        {r.flow.groundTruthLabel || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

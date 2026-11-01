/**
 * Preloaded Benchmark Datasets
 * Formatted matching the CIC-IDS2017 / CIC-IDS2018 benchmark schema.
 */

import { NetworkFlow, AttackCategory } from '../types/nids';
import { generateSyntheticFlow } from '../engine/trafficGenerator';

export interface DatasetPreset {
  id: string;
  name: string;
  description: string;
  flowCount: number;
  expectedDistribution: Record<string, string>;
  generate: () => NetworkFlow[];
}

export const SAMPLE_DATASETS: DatasetPreset[] = [
  {
    id: 'cic-ids-mixed-1000',
    name: 'CIC-IDS2017 Mixed Attack Evaluation (1,000 Flows)',
    description: 'Standard multi-class benchmark capture containing Benign HTTPS/DNS, DDoS SYN floods, PortScans, and Web Injections.',
    flowCount: 1000,
    expectedDistribution: {
      'Benign': '~80%',
      'DDoS': '~8%',
      'PortScan': '~6%',
      'BruteForce': '~3%',
      'ZeroDay': '~3%',
    },
    generate: () => {
      const flows: NetworkFlow[] = [];
      for (let i = 0; i < 1000; i++) {
        flows.push(generateSyntheticFlow());
      }
      return flows;
    },
  },
  {
    id: 'ddos-flood-400',
    name: 'DDoS LOIC Volumetric Flood Capture (400 Flows)',
    description: 'High-intensity SYN flood and volumetric bandwidth exhaustion trace directed at port 80/443 web services.',
    flowCount: 400,
    expectedDistribution: {
      'DDoS': '85%',
      'Benign': '15%',
    },
    generate: () => {
      const flows: NetworkFlow[] = [];
      for (let i = 0; i < 400; i++) {
        const type: AttackCategory = Math.random() < 0.85 ? 'DDoS' : 'Benign';
        flows.push(generateSyntheticFlow(type));
      }
      return flows;
    },
  },
  {
    id: 'portscan-recon-350',
    name: 'Nmap Multi-Vector PortScan Reconnaissance (350 Flows)',
    description: 'Stealth half-open SYN scanning, NULL scan, and aggressive port sweeping against internal IP subnet.',
    flowCount: 350,
    expectedDistribution: {
      'PortScan': '75%',
      'Benign': '25%',
    },
    generate: () => {
      const flows: NetworkFlow[] = [];
      for (let i = 0; i < 350; i++) {
        const type: AttackCategory = Math.random() < 0.75 ? 'PortScan' : 'Benign';
        flows.push(generateSyntheticFlow(type));
      }
      return flows;
    },
  },
  {
    id: 'clean-enterprise-500',
    name: 'Enterprise Production Baseline (500 Benign Flows)',
    description: '100% nominal corporate traffic including cloud API sync, secure HTTPS browsing, and DNS resolutions for False Positive rate validation.',
    flowCount: 500,
    expectedDistribution: {
      'Benign': '100%',
    },
    generate: () => {
      const flows: NetworkFlow[] = [];
      for (let i = 0; i < 500; i++) {
        flows.push(generateSyntheticFlow('Benign'));
      }
      return flows;
    },
  },
];

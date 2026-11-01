/**
 * Synthetic Network Traffic Stream Generator
 * Capable of real-time multi-flow generation (1-60 flows/sec)
 * with manual threat injection hooks.
 */

import { NetworkFlow, ProtocolType, AttackCategory } from '../types/nids';

const INTERNAL_IPS = [
  '192.168.1.105',
  '192.168.1.142',
  '192.168.1.88',
  '10.0.4.15',
  '10.0.4.22',
  '172.16.0.50',
];

const EXTERNAL_IPS = [
  '142.250.190.46',
  '151.101.65.140',
  '104.244.42.1',
  '185.199.108.153',
  '198.51.100.77',
  '203.0.113.195',
  '45.33.32.156',
  '91.189.91.38',
];

const ATTACKER_IPS = [
  '198.51.100.89',
  '203.0.113.44',
  '185.220.101.5',
  '45.154.255.88',
];

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomFloat(min: number, max: number, decimals = 2): number {
  const val = Math.random() * (max - min) + min;
  return Number(val.toFixed(decimals));
}

export function generateSyntheticFlow(forcedType?: AttackCategory): NetworkFlow {
  const id = `flw_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const now = Date.now();

  // If no forced threat, 85% probability normal, 15% random background threat
  let flowType = forcedType;
  if (!flowType) {
    const roll = Math.random();
    if (roll < 0.84) flowType = 'Benign';
    else if (roll < 0.88) flowType = 'PortScan';
    else if (roll < 0.92) flowType = 'DDoS';
    else if (roll < 0.95) flowType = 'BruteForce';
    else if (roll < 0.98) flowType = 'WebAttack';
    else flowType = 'ZeroDay';
  }

  let sourceIp = randomChoice(INTERNAL_IPS);
  let destinationIp = randomChoice(EXTERNAL_IPS);
  let sourcePort = randomInt(49152, 65535);
  let destinationPort = 443;
  let protocol: ProtocolType = 'TCP';

  let flowDurationMs = randomFloat(10, 800);
  let totalFwdPackets = randomInt(3, 20);
  let totalBwdPackets = randomInt(2, 25);
  let flowBytesPerSec = randomFloat(8000, 60000);
  let flowPacketsPerSec = randomFloat(10, 150);
  let fwdPacketLengthMean = randomFloat(100, 600);
  let bwdPacketLengthMean = randomFloat(300, 1200);
  let flowIATMeanMs = randomFloat(15, 120);

  let flagSyn = 1;
  let flagAck = 1;
  let flagFin = 0;
  let flagRst = 0;
  let flagPsh = 0;

  switch (flowType) {
    case 'DDoS': {
      // Massive packet rate, small flow duration, SYN flood
      sourceIp = randomChoice(ATTACKER_IPS);
      destinationIp = '192.168.1.100'; // Target Web Server
      destinationPort = 80;
      flowDurationMs = randomFloat(1, 45);
      totalFwdPackets = randomInt(15, 80);
      totalBwdPackets = randomInt(0, 1);
      flowPacketsPerSec = randomFloat(3500, 12000);
      flowBytesPerSec = randomFloat(4000000, 18000000);
      fwdPacketLengthMean = 64;
      bwdPacketLengthMean = 0;
      flowIATMeanMs = randomFloat(0.1, 1.2);
      flagSyn = 1;
      flagAck = 0;
      flagFin = 0;
      flagPsh = 0;
      break;
    }

    case 'PortScan': {
      // Rapid half-open probes across varied ports
      sourceIp = randomChoice(ATTACKER_IPS);
      destinationIp = '192.168.1.100';
      destinationPort = randomChoice([21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]);
      flowDurationMs = randomFloat(0.5, 30);
      totalFwdPackets = randomInt(1, 2);
      totalBwdPackets = 0;
      flowPacketsPerSec = randomFloat(100, 800);
      flowBytesPerSec = randomFloat(120, 300);
      fwdPacketLengthMean = 44;
      bwdPacketLengthMean = 0;
      flowIATMeanMs = randomFloat(1, 10);
      flagSyn = 1;
      flagAck = 0;
      flagFin = 0;
      flagRst = 0;
      break;
    }

    case 'BruteForce': {
      // Sequential attempts on SSH or FTP
      sourceIp = randomChoice(ATTACKER_IPS);
      destinationIp = '192.168.1.5'; // Internal bastion
      destinationPort = 22; // SSH
      flowDurationMs = randomFloat(400, 1800);
      totalFwdPackets = randomInt(10, 18);
      totalBwdPackets = randomInt(9, 16);
      flowPacketsPerSec = randomFloat(15, 60);
      flowBytesPerSec = randomFloat(1500, 6000);
      fwdPacketLengthMean = 180;
      bwdPacketLengthMean = 220;
      flowIATMeanMs = randomFloat(10, 35);
      flagSyn = 1;
      flagAck = 1;
      flagPsh = 1;
      break;
    }

    case 'WebAttack': {
      // Large anomalous payloads with PSH flags to web app
      sourceIp = randomChoice(ATTACKER_IPS);
      destinationIp = '192.168.1.100';
      destinationPort = 8080;
      flowDurationMs = randomFloat(80, 350);
      totalFwdPackets = randomInt(4, 9);
      totalBwdPackets = 1;
      flowPacketsPerSec = randomFloat(20, 80);
      flowBytesPerSec = randomFloat(25000, 95000);
      fwdPacketLengthMean = randomFloat(1350, 1800);
      bwdPacketLengthMean = 120;
      flowIATMeanMs = randomFloat(15, 60);
      flagSyn = 1;
      flagAck = 1;
      flagPsh = 1;
      break;
    }

    case 'Botnet': {
      // Highly periodic heartbeats
      sourceIp = randomChoice(INTERNAL_IPS);
      destinationIp = '185.220.101.5';
      destinationPort = 6667; // IRC / C2
      flowDurationMs = randomFloat(800, 2500);
      totalFwdPackets = randomInt(5, 8);
      totalBwdPackets = randomInt(2, 4);
      flowPacketsPerSec = randomFloat(1, 4);
      flowBytesPerSec = randomFloat(400, 1200);
      fwdPacketLengthMean = 85;
      bwdPacketLengthMean = 64;
      flowIATMeanMs = randomFloat(380, 420); // Low jitter
      flagSyn = 1;
      flagAck = 1;
      break;
    }

    case 'ZeroDay': {
      // Novel statistical outlier: high packet size + invalid TCP flag collision + abnormal IAT
      sourceIp = '203.0.113.199';
      destinationIp = '10.0.4.15';
      destinationPort = 49152;
      flowDurationMs = randomFloat(2500, 9000);
      totalFwdPackets = randomInt(45, 120);
      totalBwdPackets = randomInt(2, 5);
      flowPacketsPerSec = randomFloat(400, 1100);
      flowBytesPerSec = randomFloat(250000, 800000);
      fwdPacketLengthMean = randomFloat(1900, 3400); // Exceeds standard MTU / anomalous jumbo
      bwdPacketLengthMean = 40;
      flowIATMeanMs = randomFloat(0.5, 3.0);
      flagSyn = 1;
      flagFin = 1; // Collision
      flagPsh = 1;
      break;
    }

    case 'Benign':
    default: {
      // Realistic benign HTTPS/DNS/API traffic
      const service = randomChoice(['https', 'dns', 'api', 'internal']);
      if (service === 'https') {
        destinationPort = 443;
        flowBytesPerSec = randomFloat(15000, 80000);
        fwdPacketLengthMean = randomFloat(220, 550);
        bwdPacketLengthMean = randomFloat(600, 1400);
      } else if (service === 'dns') {
        protocol = 'UDP';
        destinationPort = 53;
        destinationIp = '8.8.8.8';
        flowDurationMs = randomFloat(2, 18);
        totalFwdPackets = 1;
        totalBwdPackets = 1;
        flowBytesPerSec = randomFloat(400, 1200);
        flowPacketsPerSec = randomFloat(50, 120);
        fwdPacketLengthMean = 74;
        bwdPacketLengthMean = 142;
        flagSyn = 0;
        flagAck = 0;
      } else if (service === 'api') {
        destinationPort = 8443;
        flowDurationMs = randomFloat(40, 180);
        totalFwdPackets = randomInt(3, 7);
        totalBwdPackets = randomInt(4, 9);
      }
      break;
    }
  }

  return {
    id,
    timestamp: now,
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    flowDurationMs,
    totalFwdPackets,
    totalBwdPackets,
    flowBytesPerSec,
    flowPacketsPerSec,
    fwdPacketLengthMean,
    bwdPacketLengthMean,
    flowIATMeanMs,
    flagSyn,
    flagAck,
    flagFin,
    flagRst,
    flagPsh,
    groundTruthLabel: flowType === 'Benign' ? 'BENIGN' : flowType.toUpperCase(),
  };
}

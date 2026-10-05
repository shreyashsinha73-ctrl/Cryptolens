import React from 'react';
import { 
  HelpCircle, 
  ShieldCheck, 
  Lock, 
  Key, 
  Cpu, 
  AlertTriangle, 
  BookOpen, 
  FileCode2, 
  Layers 
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Badge } from '../components/ui/badge';

export default function PlaceholderPage({ 
  title = "Help & Terminology", 
  description = "Zero-decryption cryptographic terminology and guide." 
}) {
  const terminologyList = [
    {
      term: "Zero-Decryption Wire Analysis",
      category: "Core Engine",
      badgeColor: "bg-blue-500/10 text-blue-400 border-blue-500/20",
      definition: "Extracting protocol metadata, cipher suite negotiations, SPI tags, and entropy distributions strictly from packet headers without inspecting or decrypting payload contents."
    },
    {
      term: "IKEv1 vs. IKEv2",
      category: "Key Exchange",
      badgeColor: "bg-purple-500/10 text-purple-400 border-purple-500/20",
      definition: "Internet Key Exchange protocols. IKEv1 relies on Main/Aggressive Mode phases vulnerable to identity leakage. IKEv2 simplifies negotiation into 4 basic messages and mandates cryptographic identity protection."
    },
    {
      term: "PFS (Perfect Forward Secrecy)",
      category: "Key Hygiene",
      badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
      definition: "Ensures that a compromise of long-term server private keys does not compromise past session keys. Requires Diffie-Hellman ephemeral exchanges for every child SA re-key."
    },
    {
      term: "Sweet32 Vulnerability",
      category: "Cipher Weakness",
      badgeColor: "bg-rose-500/10 text-rose-400 border-rose-500/20",
      definition: "CVE-2016-2183 collision attack against 64-bit block ciphers (3DES, Blowfish) in CBC mode when transmitting >32 GB over a single security association."
    },
    {
      term: "CNSA 2.0 / Suite B",
      category: "Compliance",
      badgeColor: "bg-amber-500/10 text-amber-400 border-amber-500/20",
      definition: "NSA Commercial National Security Algorithm Suite. Mandates AES-256-GCM, SHA-384/512, and post-quantum stateful hash/lattice cryptography for classified communications."
    },
    {
      term: "ESP (Encapsulating Security Payload)",
      category: "Data Plane",
      badgeColor: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
      definition: "IP protocol 50 providing data confidentiality, origin authentication, and replay protection. Inspected passively via SPI, sequence numbers, and statistical payload entropy."
    }
  ];

  return (
    <div className="flex-1 space-y-6 p-6 lg:p-8 overflow-y-auto bg-[#090A0F]">
      {/* Header */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-zinc-100 tracking-tight flex items-center gap-2">
          <BookOpen className="h-6 w-6 text-blue-500" /> {title}
        </h1>
        <p className="text-sm text-zinc-400 max-w-2xl">{description}</p>
      </div>

      {/* Zero Decryption Architecture Overview */}
      <Card className="bg-[#0F121C] border-[#1F2639]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            <CardTitle className="text-base text-zinc-100">Zero-Decryption Operational Assurance</CardTitle>
          </div>
          <CardDescription className="text-zinc-400 text-xs leading-relaxed">
            CryptoLens operates in strict compliance with non-intrusive monitoring standards. Raw payload data is never decrypted, stored, or reconstructed. Compliance and vulnerability findings are inferred entirely via packet structural semantics, negotiation handshakes, and machine learning telemetry.
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Cryptographic Terminology Glossary */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider font-mono">
          Cryptographic Terminology Glossary
        </h2>
        <div className="grid gap-4 md:grid-cols-2">
          {terminologyList.map((item, idx) => (
            <Card key={idx} className="bg-[#0F121C] border-[#1F2639] hover:border-blue-500/40 transition-colors">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-sm text-zinc-100">{item.term}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border font-mono ${item.badgeColor}`}>
                    {item.category}
                  </span>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  {item.definition}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}

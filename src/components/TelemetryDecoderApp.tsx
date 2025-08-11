import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { AlertCircle, CheckCircle2, Info, TriangleAlert } from "lucide-react";

// ==========================
// Protocol constants (v1.1)
// ==========================
const SOF = 0xfd; // Start-of-Frame
const EOF_V11 = 0xfe; // End-of-Frame (v1.1)
const EOF_TYPO = 0xf1; // Some docs mention 0xF1 — we accept but warn.

// Header bits 7–6 => Type
const HEADER_TYPE = {
  TELEMETRY: 0b00,
  COMMAND: 0b11,
} as const;

type DecodedFrame = {
  ok: boolean;
  warnings: string[];
  errors: string[];
  raw: number[];
  start: number;
  totalLength: number; // bytes from Header..CRC (excludes EOF)
  header: number;
  headerType: "Telemetry" | "Command" | "Unknown";
  headerFlags: number; // lower 6 bits
  sequence: number;
  payloadBytes: number[];
  crcRx: number; // received (big-endian)
  crcCalc: number; // calculated over Header..Payload
  eof: number;
  tlv: Array<{
    id: number;
    name: string;
    bytes: number;
    valueRaw: number[];
    valueDecoded: unknown;
  }>; // decoded TLVs
};

// ArgID map — fixed-size TLVs
const ArgDefs = [
  { id: 0x01, key: "millis", bytes: 4, type: "uint32", note: "internal clock" },
  { id: 0x02, key: "altitude", bytes: 4, type: "float", note: "metres (AGL)" },
  { id: 0x03, key: "vertical_velocity", bytes: 4, type: "float", note: "m/s" },
  {
    id: 0x04,
    key: "vertical_acceleration",
    bytes: 4,
    type: "float",
    note: "m/s^2",
  },
  {
    id: 0x05,
    key: "avionics_temperature",
    bytes: 2,
    type: "int16",
    note: "°C",
  },
  { id: 0x06, key: "cpu_temperature", bytes: 2, type: "int16", note: "°C" },
  { id: 0x07, key: "flight_mode", bytes: 1, type: "enum", note: "see table" },
  { id: 0x08, key: "air_brakes", bytes: 1, type: "uint8", note: "% open" },
  {
    id: 0x09,
    key: "oxidizer_temperature",
    bytes: 2,
    type: "int16",
    note: "°C",
  },
  {
    id: 0x0a,
    key: "oxidizer_pressure",
    bytes: 2,
    type: "uint16",
    note: "bar ×10",
  },
  {
    id: 0x0b,
    key: "valve_status",
    bytes: 1,
    type: "bitfield",
    note: "valve mask",
  },
  {
    id: 0x0c,
    key: "gps_lat",
    bytes: 4,
    type: "float",
    note: "decimal degrees",
  },
  {
    id: 0x0d,
    key: "gps_long",
    bytes: 4,
    type: "float",
    note: "decimal degrees",
  },
  { id: 0x0e, key: "yaw", bytes: 2, type: "int16", note: "deg ×100" },
  { id: 0x0f, key: "pitch", bytes: 2, type: "int16", note: "deg ×100" },
  { id: 0x10, key: "roll", bytes: 2, type: "int16", note: "deg ×100" },
] as const;

type Endian = "LE" | "BE";

const FLIGHT_MODES = [
  "STARTUP",
  "SENSOR_CHECK",
  "ARMED",
  "LIFT_OFF",
  "COAST_AND_CONTROL",
  "DROGUE_DESCEND",
  "MAIN_DESCEND",
  "TOUCHDOWN",
  "ABORT",
] as const;

// CRC-16 (Modbus 0xA001) — compute over Header..Payload
function crc16_modbus(bytes: number[]): number {
  let crc = 0xffff;
  for (const b of bytes) {
    crc ^= b;
    for (let j = 0; j < 8; j++) {
      if (crc & 1) crc = (crc >> 1) ^ 0xa001;
      else crc >>= 1;
    }
  }
  return crc & 0xffff;
}

// Helpers to parse integers/floats from byte arrays
function readUint16(bytes: number[], endian: Endian): number {
  return endian === "LE"
    ? bytes[0] | (bytes[1] << 8)
    : (bytes[0] << 8) | bytes[1];
}
function readInt16(bytes: number[], endian: Endian): number {
  const u = readUint16(bytes, endian);
  return u & 0x8000 ? u - 0x10000 : u;
}
function readUint32(bytes: number[], endian: Endian): number {
  if (endian === "LE")
    return (
      (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0
    );
  return (
    (((bytes[0] << 24) >>> 0) |
      (bytes[1] << 16) |
      (bytes[2] << 8) |
      bytes[3]) >>>
    0
  );
}
function readFloat32(bytes: number[], endian: Endian): number {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  if (endian === "LE") {
    view.setUint8(0, bytes[0]);
    view.setUint8(1, bytes[1]);
    view.setUint8(2, bytes[2]);
    view.setUint8(3, bytes[3]);
    return view.getFloat32(0, true);
  } else {
    view.setUint8(0, bytes[0]);
    view.setUint8(1, bytes[1]);
    view.setUint8(2, bytes[2]);
    view.setUint8(3, bytes[3]);
    return view.getFloat32(0, false);
  }
}

// Clean hex string to byte array
function hexToBytes(input: string): number[] {
  // Accept "0x", spaces, commas, newlines. Keep only hex chars.
  const clean = input.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  if (clean.length % 2 !== 0)
    throw new Error(
      "Hex string has odd length after cleaning – missing a nibble?"
    );
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    out.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return out;
}

// Format helpers
const hex2 = (n: number) => n.toString(16).toUpperCase().padStart(2, "0");
const hex4 = (n: number) => n.toString(16).toUpperCase().padStart(4, "0");

function decodeTLV(payload: number[], valueEndian: Endian) {
  const out: DecodedFrame["tlv"] = [];
  let i = 0;
  while (i < payload.length) {
    const id = payload[i++];
    const def = ArgDefs.find((d) => d.id === id);
    if (!def) {
      // Unknown ArgID: bail out of the loop; higher layer will warn
      break;
    }
    if (i + def.bytes > payload.length) {
      break; // truncated
    }
    const val = payload.slice(i, i + def.bytes);
    i += def.bytes;

    let decoded: unknown = val;
    switch (def.type) {
      case "uint8":
        decoded = val[0];
        break;
      case "uint16":
        decoded = readUint16(val, valueEndian);
        break;
      case "int16":
        decoded = readInt16(val, valueEndian);
        break;
      case "uint32":
        decoded = readUint32(val, valueEndian);
        break;
      case "float":
        decoded = readFloat32(val, valueEndian);
        break;
      case "enum":
        decoded = val[0];
        break;
      case "bitfield":
        decoded = val[0];
        break;
    }

    out.push({
      id,
      name: def.key,
      bytes: def.bytes,
      valueRaw: val,
      valueDecoded: decoded,
    });
  }
  return out;
}

// Main parser
function parseFrame(
  bytes: number[],
  opts: { valueEndian: Endian; sequenceEndian: Endian }
): DecodedFrame {
  const warnings: string[] = [];
  const errors: string[] = [];

  if (bytes.length < 1 + 1 + 1 + 2 + 2 + 1) {
    errors.push("Too short to be a valid frame.");
    return baseResult();
  }

  const start = bytes[0];
  if (start !== SOF) {
    errors.push(
      `Invalid Start-of-Frame: expected 0x${hex2(SOF)}, got 0x${hex2(start)}`
    );
  }

  const totalLength = bytes[1];
  // Expected layout: [SOF][TotalLength][Header][SeqHi?][SeqLo?][...Payload...][CRC Hi][CRC Lo][EOF]
  const expectedBytesFromHeaderThroughCRC = totalLength;
  const headerIdx = 2;
  const header = bytes[headerIdx];
  const seqIdx = headerIdx + 1;
  //const eofIdx =
  //  2 /*SOF,Len*/ + expectedBytesFromHeaderThroughCRC + 1 /*EOF byte*/ - 1; // Last index: start at 0
  const minTotal = 2 + expectedBytesFromHeaderThroughCRC + 1; // SOF + TL + (Header..CRC) + EOF
  if (bytes.length < minTotal) {
    errors.push(
      `Truncated frame: need ${minTotal} bytes total (based on TotalLength=${expectedBytesFromHeaderThroughCRC}), got ${bytes.length}.`
    );
  }

  // Sequence (2 bytes)
  const seqHi = bytes[seqIdx];
  const seqLo = bytes[seqIdx + 1];
  const sequence =
    opts.sequenceEndian === "BE" ? (seqHi << 8) | seqLo : (seqLo << 8) | seqHi;

  // Payload spans from after sequence up to the CRC (2 bytes at end of the counted region)
  const payloadStart = seqIdx + 2;
  const crcStart =
    2 /*SOF+Len*/ + expectedBytesFromHeaderThroughCRC - 2; /*CRC bytes*/
  const payloadBytes = bytes.slice(payloadStart, crcStart);

  // CRC received (big-endian per spec)
  const crcHi = bytes[crcStart];
  const crcLo = bytes[crcStart + 1];
  const crcRx = (crcHi << 8) | crcLo;

  // CRC calculated over Header..Payload
  const crcCalc = crc16_modbus(bytes.slice(headerIdx, crcStart));

  // EOF
  const eof = bytes[2 + expectedBytesFromHeaderThroughCRC];
  if (eof !== EOF_V11) {
    if (eof === EOF_TYPO) {
      warnings.push(
        `EOF is 0x${hex2(
          EOF_TYPO
        )} (typo seen in one table); spec v1.1 says 0x${hex2(EOF_V11)}.`
      );
    } else {
      errors.push(
        `Invalid End-of-Frame: expected 0x${hex2(EOF_V11)}, got 0x${hex2(eof)}`
      );
    }
  }

  // Header decode
  const typeBits = (header >> 6) & 0b11;
  const headerType =
    typeBits === HEADER_TYPE.TELEMETRY
      ? "Telemetry"
      : typeBits === HEADER_TYPE.COMMAND
      ? "Command"
      : "Unknown";
  const headerFlags = header & 0b0011_1111;

  // TLV decode
  const tlv = decodeTLV(payloadBytes, opts.valueEndian);

  // Sanity checks on TLV integrity
  const seenBytes = tlv.reduce((acc, t) => acc + 1 + t.bytes, 0);
  if (seenBytes !== payloadBytes.length) {
    const unknownAt =
      payloadBytes[seenBytes] !== undefined
        ? `0x${hex2(payloadBytes[seenBytes])}`
        : "<end>";
    warnings.push(
      `Payload parsing stopped early at byte ${seenBytes}/${payloadBytes.length}. Likely unknown ArgID (${unknownAt}) or truncated value.`
    );
  }

  if (crcRx !== crcCalc) {
    errors.push(
      `CRC mismatch: received 0x${hex4(crcRx)} but calculated 0x${hex4(
        crcCalc
      )}.`
    );
  }

  return {
    ok: errors.length === 0,
    warnings,
    errors,
    raw: bytes,
    start,
    totalLength: expectedBytesFromHeaderThroughCRC,
    header,
    headerType,
    headerFlags,
    sequence,
    payloadBytes,
    crcRx,
    crcCalc,
    eof,
    tlv,
  };

  function baseResult(): DecodedFrame {
    return {
      ok: false,
      warnings: [],
      errors,
      raw: bytes,
      start: bytes[0] ?? 0,
      totalLength: 0,
      header: 0,
      headerType: "Unknown",
      headerFlags: 0,
      sequence: 0,
      payloadBytes: [],
      crcRx: 0,
      crcCalc: 0,
      eof: 0,
      tlv: [],
    };
  }
}

// Pretty-print TLV values with units
function renderTLVRow(t: DecodedFrame["tlv"][number]): {
  label: string;
  value: string;
  hint?: string;
} {
  const idHex = `0x${hex2(t.id)}`;
  switch (t.name) {
    case "millis":
      return {
        label: `${idHex} millis`,
        value: `${t.valueDecoded as number} ms`,
      };
    case "altitude":
      return {
        label: `${idHex} altitude`,
        value: `${(t.valueDecoded as number).toFixed(2)} m`,
      };
    case "vertical_velocity":
      return {
        label: `${idHex} vertical_velocity`,
        value: `${(t.valueDecoded as number).toFixed(2)} m/s`,
      };
    case "vertical_acceleration":
      return {
        label: `${idHex} vertical_acceleration`,
        value: `${(t.valueDecoded as number).toFixed(2)} m/s²`,
      };
    case "avionics_temperature":
      return {
        label: `${idHex} avionics_temperature`,
        value: `${t.valueDecoded as number} °C`,
      };
    case "cpu_temperature":
      return {
        label: `${idHex} cpu_temperature`,
        value: `${t.valueDecoded as number} °C`,
      };
    case "flight_mode": {
      const idx = t.valueDecoded as number;
      const name = FLIGHT_MODES[idx] ?? `UNKNOWN(${idx})`;
      return { label: `${idHex} flight_mode`, value: `${idx} – ${name}` };
    }
    case "air_brakes":
      return {
        label: `${idHex} air_brakes`,
        value: `${t.valueDecoded as number}% open`,
      };
    case "oxidizer_temperature":
      return {
        label: `${idHex} oxidizer_temperature`,
        value: `${t.valueDecoded as number} °C`,
      };
    case "oxidizer_pressure": {
      const raw = t.valueDecoded as number;
      const bar = raw / 10;
      return {
        label: `${idHex} oxidizer_pressure`,
        value: `${bar.toFixed(1)} bar`,
        hint: `${raw} (×0.1 bar)`,
      };
    }
    case "valve_status": {
      const b = t.valueDecoded as number;
      const bits = Array.from({ length: 8 }, (_, i) =>
        (b >> i) & 1 ? `V${i}` : null
      )
        .filter(Boolean)
        .join(", ");
      return { label: `${idHex} valve_status`, value: bits || "none" };
    }
    case "gps_lat":
      return {
        label: `${idHex} gps_lat`,
        value: `${(t.valueDecoded as number).toFixed(6)} °`,
      };
    case "gps_long":
      return {
        label: `${idHex} gps_long`,
        value: `${(t.valueDecoded as number).toFixed(6)} °`,
      };
    case "yaw":
      return {
        label: `${idHex} yaw`,
        value: `${((t.valueDecoded as number) / 100).toFixed(2)} °`,
        hint: `${t.valueDecoded as number} (×0.01°)`,
      };
    case "pitch":
      return {
        label: `${idHex} pitch`,
        value: `${((t.valueDecoded as number) / 100).toFixed(2)} °`,
        hint: `${t.valueDecoded as number} (×0.01°)`,
      };
    case "roll":
      return {
        label: `${idHex} roll`,
        value: `${((t.valueDecoded as number) / 100).toFixed(2)} °`,
        hint: `${t.valueDecoded as number} (×0.01°)`,
      };
    default:
      return { label: `${idHex} ${t.name}`, value: String(t.valueDecoded) };
  }
}

// Build a demo telemetry frame with a few TLVs
function buildDemoFrame(opts: { valueEndian: Endian; sequenceEndian: Endian }) {
  const payload: number[] = [];
  const pushTLV = (id: number, raw: number[]) => {
    payload.push(id, ...raw);
  };
  const enc16 = (v: number) =>
    opts.valueEndian === "LE"
      ? [v & 0xff, (v >> 8) & 0xff]
      : [(v >> 8) & 0xff, v & 0xff];
  const enc32 = (v: number) => {
    if (opts.valueEndian === "LE")
      return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff];
    return [(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff];
  };
  const encF32 = (f: number) => {
    const buf = new ArrayBuffer(4);
    const dv = new DataView(buf);
    dv.setFloat32(0, f, opts.valueEndian === "LE");
    return [dv.getUint8(0), dv.getUint8(1), dv.getUint8(2), dv.getUint8(3)];
  };

  pushTLV(0x01, enc32(123456)); // millis
  pushTLV(0x02, encF32(326.5)); // altitude m
  pushTLV(0x03, encF32(-14.5)); // vertical vel
  pushTLV(0x05, enc16(25)); // avionics temp °C
  pushTLV(0x07, [3]); // flight mode LIFT_OFF
  pushTLV(0x08, [7]); // air brakes 7%
  pushTLV(0x0e, enc16(Math.round(12.34 * 100))); // yaw ×100
  pushTLV(0x0f, enc16(Math.round(-2.5 * 100))); // pitch ×100 (two's complement)

  const headerTypeBits = HEADER_TYPE.TELEMETRY << 6; // 0b00 in top bits
  const headerFlags = 0; // reserved
  const header = headerTypeBits | headerFlags;

  const sequenceVal = 42;
  const seqBytes =
    opts.sequenceEndian === "BE"
      ? [(sequenceVal >> 8) & 0xff, sequenceVal & 0xff]
      : [sequenceVal & 0xff, (sequenceVal >> 8) & 0xff];

  // Build [SOF][Len][Header][Seq][Payload][CRC][EOF]
  const headerThroughPayload = [header, ...seqBytes, ...payload];
  const crc = crc16_modbus(headerThroughPayload);
  const crcBE = [(crc >> 8) & 0xff, crc & 0xff]; // big-endian on the wire

  const totalLength = headerThroughPayload.length + 2; // + CRC bytes, excludes EOF
  const frame = [SOF, totalLength, ...headerThroughPayload, ...crcBE, EOF_V11];
  return frame.map(hex2).join("");
}

export default function TelemetryDecoderApp() {
  const [hexInput, setHexInput] = useState<string>("");
  const [valueEndian, setValueEndian] = useState<Endian>("LE"); // common on ARM
  const [seqEndian, setSeqEndian] = useState<Endian>("BE"); // conservative default

  const decoded = useMemo<DecodedFrame | null>(() => {
    if (!hexInput.trim()) return null;
    try {
      const bytes = hexToBytes(hexInput);
      return parseFrame(bytes, { valueEndian, sequenceEndian: seqEndian });
    } catch (e: any) {
      return {
        ok: false,
        warnings: [],
        errors: [e.message ?? String(e)],
        raw: [],
        start: 0,
        totalLength: 0,
        header: 0,
        headerType: "Unknown",
        headerFlags: 0,
        sequence: 0,
        payloadBytes: [],
        crcRx: 0,
        crcCalc: 0,
        eof: 0,
        tlv: [],
      };
    }
  }, [hexInput, valueEndian, seqEndian]);

  const loadDemo = () =>
    setHexInput(buildDemoFrame({ valueEndian, sequenceEndian: seqEndian }));

  return (
    <div className="mx-auto max-w-5xl p-4 space-y-6">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Rocket Telemetry Decoder</h1>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 text-sm">
            <label className="font-medium">Value endian</label>
            <select
              className="border rounded-md px-2 py-1"
              value={valueEndian}
              onChange={(e) => setValueEndian(e.target.value as Endian)}
            >
              <option value="LE">Little-endian</option>
              <option value="BE">Big-endian</option>
            </select>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <label className="font-medium">Sequence endian</label>
            <select
              className="border rounded-md px-2 py-1"
              value={seqEndian}
              onChange={(e) => setSeqEndian(e.target.value as Endian)}
            >
              <option value="BE">Big-endian</option>
              <option value="LE">Little-endian</option>
            </select>
          </div>
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Paste telemetry frame (hex)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            value={hexInput}
            onChange={(e) => setHexInput(e.target.value)}
            placeholder="e.g. FD 2A 00 00 2A 01 40 E2 01 00 … FE"
            className="font-mono h-40"
          />
          <div className="flex gap-2">
            <Button onClick={loadDemo} type="button">
              Load demo frame
            </Button>
            <Button
              variant="secondary"
              type="button"
              onClick={() => setHexInput("")}
            >
              Clear
            </Button>
          </div>
          <p className="text-sm text-muted-foreground">
            Accepts spaces, commas, newlines, and optional <code>0x</code>{" "}
            prefixes. CRC-16 is Modbus (0xA001), computed over Header..Payload,
            big-endian on the wire.
          </p>
        </CardContent>
      </Card>

      {decoded && (
        <div className="grid md:grid-cols-2 gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                Frame integrity{" "}
                {decoded.ok ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : (
                  <TriangleAlert className="w-5 h-5" />
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <KV
                label="Start-of-Frame"
                value={`0x${hex2(decoded.start)}`}
                good={decoded.start === SOF}
              />
              <KV
                label="TotalLength (Header..CRC)"
                value={`${decoded.totalLength} B`}
              />
              <KV
                label="Header"
                value={`0b${decoded.header.toString(2).padStart(8, "0")}`}
              />
              <KV label="Type" value={decoded.headerType} />
              <KV
                label="Flags (5..0)"
                value={`0b${decoded.headerFlags.toString(2).padStart(6, "0")}`}
              />
              <KV label="Sequence" value={`${decoded.sequence}`} />
              <KV
                label="Payload bytes"
                value={`${decoded.payloadBytes.length}`}
              />
              <KV label="CRC (rx)" value={`0x${hex4(decoded.crcRx)}`} />
              <KV
                label="CRC (calc)"
                value={`0x${hex4(decoded.crcCalc)}`}
                good={decoded.crcRx === decoded.crcCalc}
              />
              <KV
                label="End-of-Frame"
                value={`0x${hex2(decoded.eof)}`}
                good={decoded.eof === EOF_V11}
                warn={decoded.eof === EOF_TYPO}
              />

              {decoded.errors.length > 0 && (
                <div className="mt-2 rounded-md border border-destructive/30 bg-destructive/10 p-2">
                  <div className="flex items-center gap-2 font-medium text-destructive">
                    <AlertCircle className="w-4 h-4" /> Errors
                  </div>
                  <ul className="list-disc ml-6 text-destructive">
                    {decoded.errors.map((e, i) => (
                      <li key={i}>{e}</li>
                    ))}
                  </ul>
                </div>
              )}
              {decoded.warnings.length > 0 && (
                <div className="mt-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 p-2">
                  <div className="flex items-center gap-2 font-medium text-yellow-700">
                    <Info className="w-4 h-4" /> Warnings
                  </div>
                  <ul className="list-disc ml-6 text-yellow-700">
                    {decoded.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Decoded payload</CardTitle>
            </CardHeader>
            <CardContent>
              {decoded.tlv.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No TLVs decoded. Check ArgIDs or endianness.
                </p>
              ) : (
                <ul className="space-y-2">
                  {decoded.tlv.map((t, idx) => {
                    const row = renderTLVRow(t);
                    return (
                      <li key={idx} className="rounded-lg border p-2">
                        <div className="flex justify-between text-sm">
                          <span className="font-medium">{row.label}</span>
                          <span className="font-mono">{row.value}</span>
                        </div>
                        {row.hint && (
                          <div className="text-xs text-muted-foreground">
                            {row.hint}
                          </div>
                        )}
                        <div className="mt-1 text-xs text-muted-foreground">
                          raw: {t.valueRaw.map(hex2).join(" ")}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>Raw bytes</CardTitle>
            </CardHeader>
            <CardContent>
              {decoded.raw.length === 0 ? (
                <p className="text-sm text-muted-foreground">—</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-left">
                        <th className="py-1 pr-2">Idx</th>
                        <th className="py-1 pr-2">Hex</th>
                        <th className="py-1 pr-2">Dec</th>
                        <th className="py-1 pr-2">Meaning</th>
                      </tr>
                    </thead>
                    <tbody>
                      {decoded.raw.map((b, i) => {
                        let meaning = "";
                        if (i === 0) meaning = "SOF";
                        else if (i === 1) meaning = "TotalLength";
                        else if (i === 2) meaning = "Header";
                        else if (i === 3 || i === 4) meaning = "Sequence";
                        else if (i === 2 + decoded.totalLength - 2)
                          meaning = "CRC Hi";
                        else if (i === 2 + decoded.totalLength - 1)
                          meaning = "CRC Lo";
                        else if (i === 2 + decoded.totalLength) meaning = "EOF";
                        else meaning = "Payload";
                        return (
                          <tr key={i} className="border-t">
                            <td className="py-1 pr-2 font-mono">{i}</td>
                            <td className="py-1 pr-2 font-mono">{hex2(b)}</td>
                            <td className="py-1 pr-2 font-mono">{b}</td>
                            <td className="py-1 pr-2">{meaning}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      <footer className="text-xs text-muted-foreground">
        Spec highlights: SOF=0xFD, EOF=0xFE (v1.1), TotalLength counts
        Header..CRC, CRC-16(Modbus 0xA001) over Header..Payload, CRC stored
        big-endian. TLVs are fixed-size by ArgID.
      </footer>
    </div>
  );
}

function KV({
  label,
  value,
  good,
  warn,
}: {
  label: string;
  value: string;
  good?: boolean;
  warn?: boolean;
}) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span
        className={
          "font-mono " +
          (good ? "text-emerald-600" : warn ? "text-yellow-700" : "")
        }
      >
        {value}
      </span>
    </div>
  );
}

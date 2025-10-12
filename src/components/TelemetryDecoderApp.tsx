import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

// Header flag bits
const FLAG_VALUE_BIG = 0b000001; // TLV values big-endian if set
const FLAG_SEQ_LITTLE = 0b000010; // Sequence little-endian if set

type Endian = "LE" | "BE";

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
  valueEndian: Endian;
  sequenceEndian: Endian;
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
  command: { id: number; name: string } | null;
};

// ArgID map — fixed-size TLVs
const ArgDefs = [
  {
    id: 0x01,
    key: "millis",
    bytes: 4,
    type: "uint32",
    note: "time since boot, ms",
  },
  { id: 0x02, key: "altitude", bytes: 4, type: "float", note: "altitude AGL, m" },
  {
    id: 0x03,
    key: "vertical_velocity",
    bytes: 4,
    type: "float",
    note: "vertical speed, m/s",
  },
  {
    id: 0x04,
    key: "vertical_acceleration",
    bytes: 4,
    type: "float",
    note: "vertical accel, m/s²",
  },
  {
    id: 0x05,
    key: "avionics_temperature",
    bytes: 2,
    type: "int16",
    note: "avionics °C ×10",
  },
  {
    id: 0x06,
    key: "cpu_temperature",
    bytes: 2,
    type: "int16",
    note: "CPU °C ×10",
  },
  {
    id: 0x07,
    key: "flight_mode",
    bytes: 1,
    type: "enum",
    note: "flight-mode enum",
  },
  { id: 0x08, key: "air_brakes", bytes: 1, type: "uint8", note: "air-brakes %" },
  {
    id: 0x09,
    key: "oxidizer_temperature",
    bytes: 2,
    type: "int16",
    note: "oxidizer °C ×10",
  },
  {
    id: 0x0a,
    key: "oxidizer_pressure",
    bytes: 2,
    type: "uint16",
    note: "oxidizer pressure, bar",
  },
  {
    id: 0x0b,
    key: "valve_status",
    bytes: 1,
    type: "bitfield",
    note: "valve bitmask",
  },
  { id: 0x0c, key: "gps_lat", bytes: 4, type: "float", note: "GPS latitude" },
  { id: 0x0d, key: "gps_long", bytes: 4, type: "float", note: "GPS longitude" },
  { id: 0x0e, key: "yaw", bytes: 2, type: "int16", note: "deg ×100" },
  { id: 0x0f, key: "pitch", bytes: 2, type: "int16", note: "deg ×100" },
  { id: 0x10, key: "roll", bytes: 2, type: "int16", note: "deg ×100" },
  {
    id: 0x20,
    key: "oxidizer_pressure_1",
    bytes: 4,
    type: "float",
    note: "CM pressure, bar",
  },
  {
    id: 0x21,
    key: "oxidizer_pressure_2",
    bytes: 4,
    type: "float",
    note: "pre-injector pressure, bar",
  },
  {
    id: 0x22,
    key: "oxidizer_pressure_3",
    bytes: 4,
    type: "float",
    note: "pre-injector pressure (redundant), bar",
  },
  {
    id: 0x23,
    key: "load_cell_500n",
    bytes: 4,
    type: "float",
    note: "500N load cell",
  },
  {
    id: 0x24,
    key: "load_cell_5k",
    bytes: 4,
    type: "float",
    note: "5K load cell",
  },
] as const;

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

// Command ID map
const CommandDefs = [
  { id: 0x70, key: "LAUNCH" },
  { id: 0x80, key: "ABORT" },
  { id: 0x81, key: "SET_FLIGHT_MODE" },
  { id: 0x82, key: "SET_AIR_BRAKES" },
  { id: 0xaa, key: "ARM" },
  { id: 0xdd, key: "DISARM" },
  { id: 0xa0, key: "OPEN_MAINVALVE" },
  { id: 0xa1, key: "OPEN_SECVALVE" },
  { id: 0xa2, key: "OPEN_VENTVALVE" },
  { id: 0xa3, key: "OPEN_PURGEVALVE" },
  { id: 0xb0, key: "CLOSE_MAINVALVE" },
  { id: 0xb1, key: "CLOSE_SECVALVE" },
  { id: 0xb2, key: "CLOSE_VENTVALVE" },
  { id: 0xb3, key: "CLOSE_PURGEVALVE" },
  { id: 0xc0, key: "DETATCH_NOX_ACTUATOR" },
  { id: 0xc1, key: "DETATCH_N2_ACTUATOR" },
  { id: 0x7f, key: "PING" },
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
function parseFrame(bytes: number[]): DecodedFrame {
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
  const typeBits = (header >> 6) & 0b11;
  const headerType =
    typeBits === HEADER_TYPE.TELEMETRY
      ? "Telemetry"
      : typeBits === HEADER_TYPE.COMMAND
      ? "Command"
      : "Unknown";
  const headerFlags = header & 0b0011_1111;
  const valueEndian: Endian =
    headerFlags & FLAG_VALUE_BIG ? "BE" : "LE";
  const sequenceEndian: Endian =
    headerFlags & FLAG_SEQ_LITTLE ? "LE" : "BE";
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
    sequenceEndian === "BE" ? (seqHi << 8) | seqLo : (seqLo << 8) | seqHi;

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

  // Header decode done above
  let tlv: DecodedFrame["tlv"] = [];
  let command: { id: number; name: string } | null = null;

  if (headerType === "Telemetry") {
    tlv = decodeTLV(payloadBytes, valueEndian);

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
  } else if (headerType === "Command") {
    if (payloadBytes.length === 0) {
      warnings.push("Command frame has no Command ID byte.");
    } else {
      const cmdId = payloadBytes[0];
      const def = CommandDefs.find((c) => c.id === cmdId);
      command = {
        id: cmdId,
        name: def ? def.key : `UNKNOWN(0x${hex2(cmdId)})`,
      };
      if (payloadBytes.length > 1) {
        warnings.push(
          `Command frame has ${payloadBytes.length - 1} extra payload byte(s).`
        );
      }
    }
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
    valueEndian,
    sequenceEndian,
    sequence,
    payloadBytes,
    crcRx,
    crcCalc,
    eof,
    tlv,
    command,
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
      valueEndian: "LE",
      sequenceEndian: "BE",
      sequence: 0,
      payloadBytes: [],
      crcRx: 0,
      crcCalc: 0,
      eof: 0,
      tlv: [],
      command: null,
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
    case "oxidizer_pressure_1":
    case "oxidizer_pressure_2":
    case "oxidizer_pressure_3":
      return {
        label: `${idHex} ${t.name}`,
        value: `${(t.valueDecoded as number).toFixed(2)} bar`,
      };
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
  const headerFlags =
    (opts.valueEndian === "BE" ? FLAG_VALUE_BIG : 0) |
    (opts.sequenceEndian === "LE" ? FLAG_SEQ_LITTLE : 0);
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
  const [tab, setTab] = useState<"decode" | "generate">("decode");
  const [hexInput, setHexInput] = useState<string>("");
  const [valueEndian, setValueEndian] = useState<Endian>("LE"); // common on ARM
  const [seqEndian, setSeqEndian] = useState<Endian>("BE"); // conservative default

  // ===== Generator state =====
  const [genType, setGenType] = useState<"Telemetry" | "Command">("Telemetry");
  const [genFlags, setGenFlags] = useState<number>(0);
  const [genSeq, setGenSeq] = useState<number>(42);
  const [genEOF, setGenEOF] = useState<number>(EOF_V11);
  const [genItems, setGenItems] = useState<
    Array<{ id: number; value: string }>
  >([]);
  const [genOutHex, setGenOutHex] = useState<string>("");
  const [genErrors, setGenErrors] = useState<string[]>([]);

  const decoded = useMemo<DecodedFrame | null>(() => {
    if (!hexInput.trim()) return null;
    try {
      const bytes = hexToBytes(hexInput);
      return parseFrame(bytes);
    } catch (e) {
      return {
        ok: false,
        warnings: [],
        errors: [e instanceof Error ? e.message : String(e)],
        raw: [],
        start: 0,
        totalLength: 0,
        header: 0,
        headerType: "Unknown",
        headerFlags: 0,
        valueEndian: "LE",
        sequenceEndian: "BE",
        sequence: 0,
        payloadBytes: [],
        crcRx: 0,
        crcCalc: 0,
        eof: 0,
        tlv: [],
        command: null,
      };
    }
  }, [hexInput]);

  const loadDemo = () =>
    setHexInput(buildDemoFrame({ valueEndian, sequenceEndian: seqEndian }));

  // ====== Generator helpers ======
  const addGenItem = (id: number, value: string) =>
    setGenItems((prev) => [...prev, { id, value }]);
  const removeGenItem = (idx: number) =>
    setGenItems((prev) => prev.filter((_, i) => i !== idx));
  const clearGen = () => {
    setGenItems([]);
    setGenOutHex("");
    setGenErrors([]);
  };

  function bytesToHex(bytes: number[], joiner = "") {
    return bytes.map(hex2).join(joiner);
  }

  function encodeUInt16(n: number, endian: Endian) {
    const v = Math.max(0, Math.min(0xffff, Math.floor(n)));
    return endian === "LE"
      ? [v & 0xff, (v >> 8) & 0xff]
      : [(v >> 8) & 0xff, v & 0xff];
  }
  function encodeInt16(n: number, endian: Endian) {
    let v = Math.round(n);
    if (v < -32768 || v > 32767) v = ((v % 0x10000) + 0x10000) % 0x10000; // wrap
    let u = v < 0 ? 0x10000 + v : v; // two's complement
    u &= 0xffff;
    return endian === "LE"
      ? [u & 0xff, (u >> 8) & 0xff]
      : [(u >> 8) & 0xff, u & 0xff];
  }
  function encodeUInt32(n: number, endian: Endian) {
    const v = Math.max(0, Math.min(0xffffffff, Math.floor(n))); // clamp
    if (endian === "LE")
      return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff];
    return [(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff];
  }
  function encodeFloat32(f: number, endian: Endian) {
    const buf = new ArrayBuffer(4);
    const dv = new DataView(buf);
    dv.setFloat32(0, f, endian === "LE");
    return [dv.getUint8(0), dv.getUint8(1), dv.getUint8(2), dv.getUint8(3)];
  }

  function encodeTLVItem(
    id: number,
    valueStr: string,
    endian: Endian
  ): number[] | string {
    const def = ArgDefs.find((d) => d.id === id);
    if (!def) return `Unknown ArgID 0x${hex2(id)}`;

    const fail = (msg: string) => `Arg ${hex2(id)} (${def.key}): ${msg}`;

    try {
      switch (def.key) {
        case "millis": {
          const n = Number(valueStr);
          if (!Number.isFinite(n)) return fail("must be a number");
          return [id, ...encodeUInt32(n, endian)];
        }
        case "altitude":
        case "vertical_velocity":
        case "vertical_acceleration":
        case "gps_lat":
        case "gps_long": {
          const n = Number(valueStr);
          if (!Number.isFinite(n)) return fail("must be a float");
          return [id, ...encodeFloat32(n, endian)];
        }
        case "oxidizer_pressure_1":
        case "oxidizer_pressure_2":
        case "oxidizer_pressure_3": {
          const n = Number(valueStr);
          if (!Number.isFinite(n)) return fail("must be a float");
          return [id, ...encodeFloat32(n, endian)];
        }
        case "avionics_temperature":
        case "cpu_temperature": {
          const n = Number(valueStr);
          if (!Number.isFinite(n)) return fail("must be an integer (°C)");
          return [id, ...encodeInt16(n, endian)];
        }
        case "flight_mode": {
          const n = Number(valueStr);
          if (!Number.isInteger(n) || n < 0 || n > 255)
            return fail("enum 0..255");
          return [id, n & 0xff];
        }
        case "air_brakes": {
          const n = Number(valueStr);
          if (!Number.isInteger(n) || n < 0 || n > 100)
            return fail("percent 0..100");
          return [id, n & 0xff];
        }
        case "oxidizer_temperature": {
          const n = Number(valueStr);
          if (!Number.isFinite(n)) return fail("must be an integer (°C)");
          return [id, ...encodeInt16(n, endian)];
        }
        case "oxidizer_pressure": {
          // UI expects bar, wire is uint16 *0.1 bar
          const bar = Number(valueStr);
          if (!Number.isFinite(bar)) return fail("must be a number (bar)");
          const raw = Math.round(bar * 10);
          if (raw < 0 || raw > 65535) return fail("out of range after ×10");
          return [id, ...encodeUInt16(raw, endian)];
        }
        case "valve_status": {
          const n = Number(valueStr);
          if (!Number.isInteger(n) || n < 0 || n > 255)
            return fail("bitmask 0..255");
          return [id, n & 0xff];
        }
        case "yaw":
        case "pitch":
        case "roll": {
          // UI expects degrees, wire is int16 ×100
          const deg = Number(valueStr);
          if (!Number.isFinite(deg)) return fail("must be a number (degrees)");
          const raw = Math.round(deg * 100);
          return [id, ...encodeInt16(raw, endian)];
        }
        default:
          return fail("unsupported field");
      }
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e));
    }
  }

  function buildGeneratedFrame() {
    const errs: string[] = [];
    const payload: number[] = [];
    for (let i = 0; i < genItems.length; i++) {
      const { id, value } = genItems[i];
      const encoded = encodeTLVItem(id, value, valueEndian);
      if (typeof encoded === "string") {
        errs.push(encoded);
        continue;
      }
      payload.push(...encoded);
    }

    if (genType !== "Telemetry") {
      errs.push(
        "Command frames: payload builder not implemented yet (needs CmdID table wiring)."
      );
    }

    if (errs.length) {
      setGenErrors(errs);
      setGenOutHex("");
      return;
    }

    // Header
    const headerTypeBits =
      genType === "Telemetry"
        ? HEADER_TYPE.TELEMETRY << 6
        : HEADER_TYPE.COMMAND << 6;
    const autoFlags =
      (valueEndian === "BE" ? FLAG_VALUE_BIG : 0) |
      (seqEndian === "LE" ? FLAG_SEQ_LITTLE : 0);
    const userFlags = genFlags & 0b0011_1111;
    const headerFlags =
      (userFlags & ~(FLAG_VALUE_BIG | FLAG_SEQ_LITTLE)) | autoFlags;
    const header = (headerTypeBits | headerFlags) & 0xff;

    // Sequence
    let seqHi: number, seqLo: number;
    const s = Math.max(0, Math.min(0xffff, Math.floor(genSeq)));
    if (seqEndian === "BE") {
      seqHi = (s >> 8) & 0xff;
      seqLo = s & 0xff;
    } else {
      seqHi = s & 0xff;
      seqLo = (s >> 8) & 0xff;
    }

    const headerThroughPayload = [header, seqHi, seqLo, ...payload];
    const crc = crc16_modbus(headerThroughPayload);
    const crcBE = [(crc >> 8) & 0xff, crc & 0xff];
    const totalLength = headerThroughPayload.length + 2; // +CRC

    const frame = [SOF, totalLength, ...headerThroughPayload, ...crcBE, genEOF];
    const hex = bytesToHex(frame, "");
    setGenOutHex(hex);
    setGenErrors([]);
  }

  const loadGenIntoDecoder = () => {
    if (genOutHex) {
      setHexInput(genOutHex);
      setTab("decode");
    }
  };

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

      {/* Simple tabs */}
      <div className="flex gap-2">
        <Button
          variant={tab === "decode" ? undefined : "secondary"}
          onClick={() => setTab("decode")}
        >
          Decode
        </Button>
        <Button
          variant={tab === "generate" ? undefined : "secondary"}
          onClick={() => setTab("generate")}
        >
          Generate
        </Button>
      </div>

      {tab === "decode" && (
        <>
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
                prefixes. CRC-16 is Modbus (0xA001), computed over
                Header..Payload, big-endian on the wire.
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
                    value={`0b${decoded.headerFlags
                      .toString(2)
                      .padStart(6, "0")}`}
                  />
                  <KV label="Value endian" value={decoded.valueEndian} />
                  <KV
                    label="Sequence endian"
                    value={decoded.sequenceEndian}
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
                  {decoded.headerType === "Command" ? (
                    decoded.command ? (
                      <p className="text-sm">
                        Command: 0x{hex2(decoded.command.id)} {decoded.command.name}
                      </p>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No Command ID decoded.
                      </p>
                    )
                  ) : decoded.tlv.length === 0 ? (
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
                            else if (i === 2 + decoded.totalLength)
                              meaning = "EOF";
                            else meaning = "Payload";
                            return (
                              <tr key={i} className="border-t">
                                <td className="py-1 pr-2 font-mono">{i}</td>
                                <td className="py-1 pr-2 font-mono">
                                  {hex2(b)}
                                </td>
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
        </>
      )}

      {tab === "generate" && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Build a telemetry frame</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid sm:grid-cols-2 gap-3 text-sm">
                <label className="flex items-center justify-between gap-2">
                  Type
                  <select
                    className="border rounded-md px-2 py-1"
                    value={genType}
                    onChange={(e) =>
                      setGenType(e.target.value as "Telemetry" | "Command")
                    }
                  >
                    <option>Telemetry</option>
                    <option>Command</option>
                  </select>
                </label>
                <label className="flex items-center justify-between gap-2">
                  Flags (0..63)
                  <input
                    type="number"
                    className="border rounded-md px-2 py-1 w-28"
                    value={genFlags}
                    min={0}
                    max={63}
                    onChange={(e) => setGenFlags(Number(e.target.value))}
                  />
                </label>
                <label className="flex items-center justify-between gap-2">
                  Sequence (0..65535)
                  <input
                    type="number"
                    className="border rounded-md px-2 py-1 w-28"
                    value={genSeq}
                    min={0}
                    max={65535}
                    onChange={(e) => setGenSeq(Number(e.target.value))}
                  />
                </label>
                <label className="flex items-center justify-between gap-2">
                  EOF
                  <select
                    className="border rounded-md px-2 py-1"
                    value={genEOF}
                    onChange={(e) => setGenEOF(Number(e.target.value))}
                  >
                    <option value={EOF_V11}>0xFE (v1.1)</option>
                    <option value={EOF_TYPO}>0xF1 (compat)</option>
                  </select>
                </label>
              </div>

              <div className="rounded-md border p-3 space-y-3">
                <div className="font-medium">Add TLVs</div>
                <TLVAdder onAdd={addGenItem} />
                {genItems.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    No TLVs yet — add some above.
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {genItems.map((it, idx) => {
                      const def = ArgDefs.find((d) => d.id === it.id)!;
                      const preview = encodeTLVItem(
                        it.id,
                        it.value,
                        valueEndian
                      );
                      const err = typeof preview === "string" ? preview : null;
                      const raw = Array.isArray(preview)
                        ? preview.slice(1)
                        : [];
                      const dec = Array.isArray(preview)
                        ? decodeTLV(preview, valueEndian)[0]
                        : undefined;
                      return (
                        <li key={idx} className="rounded-lg border p-2 text-sm">
                          <div className="flex items-center justify-between gap-2">
                            <div>
                              <div className="font-medium">
                                0x{hex2(def.id)} {def.key}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                value:{" "}
                                <span className="font-mono">{it.value}</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {err ? (
                                <span className="text-red-600 text-xs">
                                  {err}
                                </span>
                              ) : (
                                <span className="text-xs text-muted-foreground">
                                  raw: {raw.map(hex2).join(" ")}
                                </span>
                              )}
                              <Button
                                variant="secondary"
                                onClick={() => removeGenItem(idx)}
                              >
                                Remove
                              </Button>
                            </div>
                          </div>
                          {dec && (
                            <div className="mt-1 text-xs">
                              as decoded →{" "}
                              {renderTLVRow(dec).value}
                            </div>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                )}

                <div className="flex gap-2">
                  <Button onClick={buildGeneratedFrame}>Build frame</Button>
                  <Button variant="secondary" onClick={clearGen}>
                    Clear
                  </Button>
                </div>

                {genErrors.length > 0 && (
                  <div className="mt-2 rounded-md border border-destructive/30 bg-destructive/10 p-2">
                    <div className="flex items-center gap-2 font-medium text-destructive">
                      <AlertCircle className="w-4 h-4" /> Errors
                    </div>
                    <ul className="list-disc ml-6 text-destructive text-sm">
                      {genErrors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {genOutHex && (
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Frame (hex)</div>
                    <Textarea
                      className="font-mono h-32"
                      value={genOutHex}
                      readOnly
                    />
                    <div className="flex gap-2">
                      <Button
                        type="button"
                        onClick={() => {
                          navigator.clipboard?.writeText(genOutHex);
                        }}
                      >
                        Copy hex
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        onClick={loadGenIntoDecoder}
                      >
                        Load into decoder
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </>
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

// Minimal TLV adder UI
function TLVAdder({ onAdd }: { onAdd: (id: number, value: string) => void }) {
  const [id, setId] = useState<number>(ArgDefs[0].id);
  const [value, setValue] = useState<string>("");
  const def = ArgDefs.find((d) => d.id === id)!;
  return (
    <div className="grid md:grid-cols-[200px_1fr_auto] gap-2 items-end">
      <label className="text-sm">
        <div className="mb-1 font-medium">Arg</div>
        <select
          className="border rounded-md px-2 py-1 w-full"
          value={id}
          onChange={(e) => setId(Number(e.target.value))}
        >
          {ArgDefs.map((d) => (
            <option key={d.id} value={d.id}>
              0x{hex2(d.id)} — {d.key}
            </option>
          ))}
        </select>
      </label>

      <label className="text-sm">
        <div className="mb-1 font-medium">
          Value{" "}
          {def.key === "oxidizer_pressure"
            ? "(bar)"
            : def.key === "yaw" || def.key === "pitch" || def.key === "roll"
            ? "(deg)"
            : ""}
        </div>
        <Input
          placeholder={placeholderFor(def.key)}
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <div className="text-xs text-muted-foreground mt-1">
          {hintFor(def.key)}
        </div>
      </label>

      <div>
        <Button
          onClick={() => {
            if (value.trim() !== "") {
              onAdd(id, value.trim());
              setValue("");
            }
          }}
        >
          Add
        </Button>
      </div>
    </div>
  );
}

function placeholderFor(key: string) {
  switch (key) {
    case "millis":
      return "123456";
    case "altitude":
      return "326.5";
    case "vertical_velocity":
      return "-14.5";
    case "vertical_acceleration":
      return "0.0";
    case "avionics_temperature":
    case "cpu_temperature":
      return "25";
    case "flight_mode":
      return "0..8";
    case "air_brakes":
      return "0..100";
    case "oxidizer_temperature":
      return "20";
    case "oxidizer_pressure":
      return "12.3  (bar)";
    case "oxidizer_pressure_1":
    case "oxidizer_pressure_2":
    case "oxidizer_pressure_3":
      return "12.3  (bar)";
    case "valve_status":
      return "bitmask 0..255";
    case "gps_lat":
      return "38.736946";
    case "gps_long":
      return "-9.142685";
    case "yaw":
    case "pitch":
    case "roll":
      return "12.34  (deg)";
    default:
      return "";
  }
}
function hintFor(key: string) {
  switch (key) {
    case "oxidizer_pressure":
      return "Will be encoded as uint16 of (bar × 10).";
    case "oxidizer_pressure_1":
    case "oxidizer_pressure_2":
    case "oxidizer_pressure_3":
      return "Will be encoded as float32.";
    case "yaw":
    case "pitch":
    case "roll":
      return "Will be encoded as int16 of (deg × 100).";
    default:
      return "";
  }
}

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import i18n from "@/i18n";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const lang = () => i18n.resolvedLanguage ?? "en";

export function fmtDate(v?: string | null, withTime = false) {
  if (!v || v.startsWith("0001-")) return "—";
  const d = new Date(v);
  return new Intl.DateTimeFormat(lang(), withTime ? { dateStyle: "medium", timeStyle: "short" } : { dateStyle: "medium" }).format(d);
}

export function daysUntil(v: string) {
  return Math.ceil((new Date(v).getTime() - Date.now()) / 86_400_000);
}

export function fmtRelative(v?: string | null) {
  if (!v || v.startsWith("0001-")) return "—";
  const diff = (new Date(v).getTime() - Date.now()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(lang(), { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 86400 * 60) return rtf.format(Math.round(diff / 86400), "day");
  if (abs < 86400 * 730) return rtf.format(Math.round(diff / (86400 * 30)), "month");
  return rtf.format(Math.round(diff / (86400 * 365)), "year");
}

export function fmtNumber(n: number) {
  return new Intl.NumberFormat(lang()).format(n);
}

export function isZeroTime(v?: string | null) {
  return !v || v.startsWith("0001-");
}

export function downloadText(filename: string, text: string, type = "application/x-pem-file") {
  downloadBlob(filename, new Blob([text], { type }));
}

export function downloadBase64(filename: string, b64: string, type = "application/x-pkcs12") {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  downloadBlob(filename, new Blob([bytes], { type }));
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function shortFingerprint(fp: string) {
  return fp.length > 23 ? `${fp.slice(0, 11)}…${fp.slice(-11)}` : fp;
}

/** Formats a hex fingerprint as AA:BB:CC… */
export function colonHex(hex: string) {
  return hex.replace(/:/g, "").toUpperCase().match(/.{1,2}/g)?.join(":") ?? hex;
}

/** Mirrors ca.ValidSlug on the server. */
export function validSlug(s: string) {
  return /^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$/.test(s) && !s.includes("--");
}

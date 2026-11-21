import { useId } from "react";
import { cn } from "@/lib/utils";

/**
 * Conrad "APPROVED" stamp: green seal, dashed ring, ring text, and a padlock whose
 * shackle is made of dreadlocks ("locks") wearing bureaucrat glasses. Original artwork.
 */
export function Logo({
  size = 40,
  tone = "brand",
  simple = false,
  className,
  title = "Conrad",
}: {
  size?: number;
  tone?: "brand" | "inverse";
  simple?: boolean;
  className?: string;
  title?: string;
}) {
  const id = useId().replace(/:/g, "");
  const disc = tone === "brand" ? "#3F6B35" : "#FAF7EE";
  const ink = tone === "brand" ? "#FAF7EE" : "#2B4C24";
  const hair = tone === "brand" ? "#FAF7EE" : "#4A3424";
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" role="img" aria-label={title} className={cn("shrink-0", className)}>
      <circle cx="64" cy="64" r="62" fill={disc} />
      {!simple && (
        <>
          <circle cx="64" cy="64" r="57" fill="none" stroke={ink} strokeWidth="2" />
          <circle cx="64" cy="64" r="41" fill="none" stroke={ink} strokeWidth="1.6" strokeDasharray="3.2 2.6" />
          <path id={`ring-${id}`} d="M64 64 m-49 0 a49 49 0 1 1 98 0 a49 49 0 1 1 -98 0" fill="none" />
          <text fill={ink} fontFamily="Inter Variable, Inter, system-ui, sans-serif" fontSize="9.6" fontWeight="800" letterSpacing="1.2">
            <textPath href={`#ring-${id}`} startOffset="0" textLength="300" lengthAdjust="spacing">
              CONRAD · CERTIFIED · APPROVED ·
            </textPath>
          </text>
        </>
      )}
      <Lock hair={hair} ink={ink} disc={disc} scale={simple ? 1.35 : 1} />
    </svg>
  );
}

function Lock({ hair, ink, disc, scale }: { hair: string; ink: string; disc: string; scale: number }) {
  const twist = { stroke: disc, strokeOpacity: 0.45, strokeWidth: 1.4, strokeDasharray: "1.6 2.8", fill: "none", strokeLinecap: "round" as const };
  const loc = { stroke: hair, strokeWidth: 4.6, fill: "none", strokeLinecap: "round" as const };
  const arches = ["M47 64 C47 31 81 31 81 64", "M53.5 64 C53.5 39 74.5 39 74.5 64"];
  const dangles = ["M47 63 C43.5 70 46 77 42 85", "M81 63 C84.5 70 82 77 86 85"];
  return (
    <g transform={`translate(64 64) scale(${scale}) translate(-64 -66)`}>
      {arches.map((d) => (
        <g key={d}>
          <path d={d} {...loc} />
          <path d={d} {...twist} />
        </g>
      ))}
      <rect x="45" y="61" width="38" height="29" rx="5.5" fill={ink} />
      {dangles.map((d) => (
        <g key={d}>
          <path d={d} {...loc} strokeWidth={4} />
          <path d={d} {...twist} />
        </g>
      ))}
      <circle cx="42" cy="86" r="2.6" fill={hair} />
      <circle cx="86" cy="86" r="2.6" fill={hair} />
      {/* bureaucrat glasses */}
      <circle cx="57" cy="73.5" r="5.6" fill="none" stroke={disc} strokeWidth="2.3" />
      <circle cx="71" cy="73.5" r="5.6" fill="none" stroke={disc} strokeWidth="2.3" />
      <path d="M62.4 73 q1.6 -2.2 3.2 0" fill="none" stroke={disc} strokeWidth="2" strokeLinecap="round" />
      <path d="M64 81.5 v4" stroke={disc} strokeWidth="2.6" strokeLinecap="round" />
    </g>
  );
}

import * as React from 'react'
import { LAUREL_SPINE, laurelPoint, laurelTangent, type GlyphName } from './seal-art'

/* Resident glyphs drawn bare as line symbols on a 32x32 box: the same
   shapes as the printed seal plates, stroked in one colour (currentColor),
   so a caller can set each resident's own ink. Identity never animates. */

/* Where the laurel's leaves sit along the spine. */
const LAUREL_STOPS = [0.2, 0.37, 0.54, 0.71, 0.88] as const
/* Distance from the spine to a leaf centre. */
const LAUREL_LEAF_OFFSET = 2.4

export interface LaurelLeaf {
  cx: number
  cy: number
  /* Rotation of the leaf ellipse in degrees. */
  deg: number
}

/* The leaves of the left half of the laurel: centred 2.4 off the spine
   along its normal, turned 0.75 rad off the spine's direction. Pure, so it
   is tested without a DOM. */
export function laurelLeaves(): LaurelLeaf[] {
  return LAUREL_STOPS.map((t) => {
    const [x, y] = laurelPoint(t)
    const [dx, dy] = laurelTangent(t)
    const len = Math.hypot(dx, dy)
    const angle = Math.atan2(dy, dx)
    return {
      cx: x - (dy / len) * LAUREL_LEAF_OFFSET,
      cy: y + (dx / len) * LAUREL_LEAF_OFFSET,
      deg: ((angle - 0.75) * 180) / Math.PI,
    }
  })
}

const MIRROR = 'matrix(-1 0 0 1 32 0)'
const WING = 'M15.6 25 C13 14 8 6 1.2 4 L2.2 11.4 L5.8 12.2 L4.4 16.6 L8.6 17.2 L8.4 21.2 L12.4 21.4 Z'
const [P0, P1, P2, P3] = LAUREL_SPINE
const LAUREL_STEM = `M${P0[0]} ${P0[1]} C${P1[0]} ${P1[1]} ${P2[0]} ${P2[1]} ${P3[0]} ${P3[1]}`

/* Ruler ticks: nine, alternate long and short, on the diagonal ruler. */
const RULER_TICKS = Array.from({ length: 9 }, (_, i) => {
  const x = (-11.2 + i * 2.8).toFixed(1)
  return `M${x} -2.6 L${x} ${i % 2 ? -0.2 : 2.6}`
}).join(' ')

function LaurelHalf() {
  return (
    <>
      <path d={LAUREL_STEM} />
      {laurelLeaves().map((leaf, i) => (
        <ellipse
          key={i}
          cx={leaf.cx.toFixed(2)}
          cy={leaf.cy.toFixed(2)}
          rx="3.2"
          ry="1.3"
          transform={`rotate(${leaf.deg.toFixed(1)} ${leaf.cx.toFixed(2)} ${leaf.cy.toFixed(2)})`}
          fill="currentColor"
          stroke="none"
        />
      ))}
    </>
  )
}

const LINES: Record<GlyphName, () => React.ReactNode> = {
  /* Two open wings over a small body. */
  wing: () => (
    <>
      <path d={WING} />
      <path d={WING} transform={MIRROR} />
      <ellipse cx="16" cy="25" rx="1.8" ry="3.4" fill="currentColor" stroke="none" />
    </>
  ),
  /* An owl's face: ear tufts, two eyes, a beak. */
  owl: () => (
    <>
      <path d="M8.6 12 L6.4 4.6 L12.4 8.8 Q16 7.6 19.6 8.8 L25.6 4.6 L23.4 12 Q26.6 18 24 24 Q20.6 29.4 16 29.4 Q11.4 29.4 8 24 Q5.4 18 8.6 12 Z" />
      <circle cx="11.6" cy="14.8" r="3.4" />
      <circle cx="20.4" cy="14.8" r="3.4" />
      <path d="M14.6 19 L17.4 19 L16 22 Z" fill="currentColor" stroke="none" />
    </>
  ),
  /* A laurel wreath: two curved stems with leaves. */
  laurel: () => (
    <>
      <g>
        <LaurelHalf />
      </g>
      <g transform={MIRROR}>
        <LaurelHalf />
      </g>
    </>
  ),
  /* A ruler laid on the diagonal. */
  ruler: () => (
    <g transform="translate(16 16) rotate(-45)">
      <rect x="-14" y="-3" width="28" height="6" rx="0.8" />
      <path d={RULER_TICKS} strokeWidth="1.6" />
    </g>
  ),
  /* A crescent moon with a small star. */
  moon: () => (
    <>
      <path d="M16 4a8 8 0 0 0 12 12 12 12 0 1 1-12-12Z" />
      <path d="M25.3 3.2v5.4M28 5.9h-5.4" />
    </>
  ),
}

export interface GlyphLineProps extends Omit<React.ComponentPropsWithRef<'svg'>, 'children'> {
  name: GlyphName
  /* Rendered size in CSS pixels. */
  size: number
  /* Stroke width in the 32 box. */
  weight?: number
}

/* One resident glyph as a line symbol in currentColor. Decorative: the
   element that holds it carries the name. */
export function GlyphLine({ name, size, weight = 2.2, ...props }: GlyphLineProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      stroke="currentColor"
      strokeWidth={weight}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {LINES[name]()}
    </svg>
  )
}

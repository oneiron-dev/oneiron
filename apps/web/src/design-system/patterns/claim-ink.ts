/* Confidence as ink: a claim prints on the ink ladder by how sure the
   memory is. 0.9 and up prints ink-1, 0.7 up to 0.9 ink-2, 0.4 up to 0.7
   ink-3, below 0.4 the faint ink-4. */

export type ClaimInk = 1 | 2 | 3 | 4

export function claimInk(confidence: number): ClaimInk {
  if (confidence >= 0.9) return 1
  if (confidence >= 0.7) return 2
  if (confidence >= 0.4) return 3
  return 4
}

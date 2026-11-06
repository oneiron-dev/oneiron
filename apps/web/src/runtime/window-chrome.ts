/** Apply a native chrome inset only on the shell that owns it. */
export function clampTunerY(y: number, windowChrome: string | undefined, cssInset: string): number {
  if (windowChrome !== 'macos') return y
  const inset = Number.parseFloat(cssInset)
  const minimum = Number.isFinite(inset) ? Math.max(0, inset) : 0
  return Math.max(minimum, y)
}

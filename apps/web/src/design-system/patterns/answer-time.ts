/* The time an answer was given, as its record line shows it: hours and
   minutes on the 24-hour clock, `09:14`. */
export function formatAnswerTime(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`
}

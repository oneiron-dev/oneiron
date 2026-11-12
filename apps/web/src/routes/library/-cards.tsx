import * as React from 'react'
import { BarChart, ComposedCard, Figure, Glyph, TaskFlow, type BarPeriod } from '~/design-system'

/* Gallery fixtures for the cards an agent composes: a table of stores, a
   weekly chart with two readings, and the tasks of one message. */

export const TABLE_NOTE =
  'Metryon built this card from Acme store sales. An agent can only compose the app’s own parts: text, tables, charts, figures, picks, fields and verbs.'

const STORES: Array<{ id: string; name: string; region: string; lastOrder: string; in: boolean }> = [
  { id: 'kobe', name: 'Kobe Sannomiya', region: 'Hyogo', lastOrder: '4 Nov', in: true },
  { id: 'umeda', name: 'Osaka Umeda', region: 'Osaka', lastOrder: '2 Nov', in: true },
  { id: 'shijo', name: 'Kyoto Shijo', region: 'Kyoto', lastOrder: '28 Oct', in: true },
  { id: 'sanjo', name: 'Nara Sanjo', region: 'Nara', lastOrder: '9 Sep', in: false },
]
/* Of the ten rows not shown, nine are in. */
const HIDDEN_IN = 9
const TOTAL = 14

/* The stores card: a table with a pick column; the count follows the picks. */
export function TableCard({ bare, onLog }: { bare?: boolean; onLog?: (line: string) => void }) {
  const [picked, setPicked] = React.useState<Record<string, boolean>>(() => Object.fromEntries(STORES.map((s) => [s.id, s.in])))
  const count = HIDDEN_IN + Object.values(picked).filter(Boolean).length
  return (
    <ComposedCard title="Stores in the pilot" note={TABLE_NOTE} bare={bare} onOpen={() => onLog?.('stores card: opened beside the room')}>
      <ComposedCard.Table
        aria-label="stores in the pilot"
        onToggle={(row, on) => {
          setPicked((p) => ({ ...p, [row]: on }))
          onLog?.(`${STORES.find((s) => s.id === row)?.name}: ${on ? 'in' : 'out'}`)
        }}
      >
        <ComposedCard.Head>
          <ComposedCard.Cell>store</ComposedCard.Cell>
          <ComposedCard.Cell>region</ComposedCard.Cell>
          <ComposedCard.Cell>last order</ComposedCard.Cell>
          <ComposedCard.Cell pick>in</ComposedCard.Cell>
        </ComposedCard.Head>
        {STORES.map((s) => (
          <ComposedCard.Row key={s.id}>
            <ComposedCard.Cell>{s.name}</ComposedCard.Cell>
            <ComposedCard.Cell>{s.region}</ComposedCard.Cell>
            <ComposedCard.Cell figure>{s.lastOrder}</ComposedCard.Cell>
            <ComposedCard.PickCell row={s.id} label={s.name} picked={picked[s.id]} />
          </ComposedCard.Row>
        ))}
      </ComposedCard.Table>
      <ComposedCard.Foot
        count={`${count} of ${TOTAL} in`}
        more="show 10 more"
        onMore={() => onLog?.('stores card: show 10 more')}
        action="use this list"
        onAction={() => onLog?.(`stores card: used the list of ${count}`)}
      />
    </ComposedCard>
  )
}

/* Weeks 40 to 52: sold through week 45, then the fit under each reading;
   last year's weeks as rings. Illustrative figures. */
const WEEKS = Array.from({ length: 13 }, (_, i) => 40 + i)
const SOLD = [3.9, 4.1, 4.0, 4.2, 3.3, 3.1]
const FIT: Record<Reading, number[]> = {
  promo: [3.2, 4.3, 4.5, 4.7, 5.2, 5.6, 3.8],
  normal: [3.2, 4.0, 4.2, 4.4, 4.8, 5.2, 3.5],
}
const LAST_YEAR = [3.7, 3.9, 3.9, 4.0, 3.2, 3.0, 3.1, 4.1, 4.3, 4.4, 4.9, 5.3, 3.6]

export type Reading = 'promo' | 'normal'

const seriesOf = (reading: Reading): BarPeriod[] => [...SOLD, ...FIT[reading]].map((value, i) => ({ label: String(WEEKS[i]), value }))
const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0)
const quarter = (reading: Reading) => sum(SOLD) + sum(FIT[reading])
const yen = (m: number) => `¥${m.toFixed(1)}M`

export const CHART_TITLE = `Promo weeks or not moves the quarter by ${yen(Math.abs(quarter('promo') - quarter('normal')))}`
export const CHART_NOTE =
  'Metryon built this card from Acme store sales: 214 stores, sold through week 45. The fit is its own forecast; the rings are last year’s sales for the same weeks.'

/* The chart card: the weekly chart, its two readings and the quarter's
   figures under the chosen one. */
export function ChartCard({
  bare,
  defaultReading = 'promo',
  onLog,
  specimen,
}: {
  bare?: boolean
  defaultReading?: Reading
  onLog?: (line: string) => void
  specimen?: string
}) {
  const [reading, setReading] = React.useState<Reading>(defaultReading)
  const other: Reading = reading === 'promo' ? 'normal' : 'promo'
  return (
    <ComposedCard title={CHART_TITLE} note={CHART_NOTE} bare={bare} onOpen={() => onLog?.('chart card: opened beside the room')} data-specimen={specimen}>
      <BarChart
        series={seriesOf(reading)}
        measuredCount={SOLD.length}
        compare={LAST_YEAR}
        range={{ from: 4, to: 6, label: 'weeks 44 to 46' }}
        measuredLabel="sold"
        forecastLabel="the fit"
        compareLabel="the same week last year"
        unit="¥ million a week"
        formatValue={(v) => v.toFixed(1)}
        ariaLabel={`Weekly sales, weeks 40 to 52: sold through week 45, then the fit with weeks 44 to 46 as ${reading} weeks; rings mark the same week last year.`}
      />
      <ComposedCard.Picks
        aria-label="reading of weeks 44 to 46"
        value={reading}
        onValueChange={(v) => {
          setReading(v as Reading)
          onLog?.(`chart card: ${v} reading`)
        }}
      >
        <ComposedCard.Reading value="promo">weeks 44 to 46 as promo weeks</ComposedCard.Reading>
        <ComposedCard.Reading value="normal">as normal weeks</ComposedCard.Reading>
      </ComposedCard.Picks>
      <ComposedCard.Figures>
        <Figure>{yen(quarter(reading))}</Figure> for the quarter this way, <Figure>{yen(quarter(other))}</Figure> the other way,{' '}
        <Figure>{yen(sum(LAST_YEAR))}</Figure> last year
      </ComposedCard.Figures>
    </ComposedCard>
  )
}

/* The three tasks of Metryon's message, in the order they feed each other. */
export function TasksFlow({ onOpen }: { onOpen?: (id: string) => void }) {
  return (
    <TaskFlow aria-label="the tasks of this message" onOpen={onOpen} data-specimen="task-flow">
      <TaskFlow.Task id="pull" done who={<Glyph glyph="owl" label="Tory" size={16} />}>
        pull Acme store sales
      </TaskFlow.Task>
      <TaskFlow.Task id="fit" arcs={['done', 'working', 'ahead']} needsYou who={<Glyph glyph="ruler" label="Metryon" size={16} />}>
        fit the Q4 forecast
      </TaskFlow.Task>
      <TaskFlow.Task id="draft" arcs={['ahead']} who={<Glyph glyph="laurel" label="Antevon" size={16} />}>
        draft the supplier outlook
      </TaskFlow.Task>
    </TaskFlow>
  )
}

import * as React from 'react'
import {
  Glyph,
  MessageRow,
  NeedsYou,
  ProgressDonut,
  SettledCard,
  TaskList,
  TaskRow,
  VersionSwitch,
  type DonutArc,
} from '~/design-system'
import { Section, Specimen } from './-gallery-frame'
import { ANTEVON, EIRI, METRYON, TORY, type Resident } from './-identity'

/* Sections of the /library gallery for split work: the progress donut, a
   message's tasks, the version switch under a reply, and settled asks.
   Every demo works on fixture data from the app's cast. */

const line = (r: Resident, size: 18 | 24 = 18) => (
  <Glyph glyph={r.glyph} label={r.name} form="line" ink={r.ink} size={size} />
)

const arcs = (...states: DonutArc[]) => states
const repeat = (state: DonutArc, n: number): DonutArc[] => Array.from({ length: n }, () => state)

/* ── the donut ────────────────────────────────────────────────────────── */

function DonutSpecimens() {
  return (
    <>
      <Specimen name="1 of 3 done, one working">
        <span className="lib-inline">
          <ProgressDonut arcs={arcs('done', 'working', 'ahead')} />
          <ProgressDonut arcs={arcs('done', 'working', 'ahead')} size={14} />
        </span>
      </Specimen>
      <Specimen name="waits on you: a dot">
        <span className="lib-inline">
          <ProgressDonut arcs={arcs('done', 'working', 'ahead')} needsYou data-specimen="donut-waits" />
          <ProgressDonut arcs={arcs('done', 'working', 'ahead')} needsYou size={14} />
        </span>
      </Specimen>
      <Specimen name="all done: a check">
        <span className="lib-inline">
          <ProgressDonut arcs={repeat('done', 3)} />
          <ProgressDonut arcs={repeat('done', 3)} size={14} />
        </span>
      </Specimen>
      <Specimen name="a failed task, dashed">
        <span className="lib-inline">
          <ProgressDonut arcs={arcs('done', 'failed', 'ahead')} />
          <ProgressDonut arcs={arcs('done', 'failed', 'ahead')} size={14} />
        </span>
      </Specimen>
      <Specimen name="one task, working">
        <span className="lib-inline">
          <ProgressDonut arcs={arcs('working')} />
          <ProgressDonut arcs={arcs('working')} size={14} />
        </span>
      </Specimen>
      <Specimen name="twelve, one arc each">
        <span className="lib-inline">
          <ProgressDonut arcs={[...repeat('done', 7), 'working', ...repeat('ahead', 4)]} />
          <ProgressDonut arcs={[...repeat('done', 7), 'working', ...repeat('ahead', 4)]} size={14} />
        </span>
      </Specimen>
      <Specimen name="twenty: the done share, smooth">
        <span className="lib-inline">
          <ProgressDonut arcs={[...repeat('done', 13), ...repeat('ahead', 7)]} />
          <ProgressDonut arcs={[...repeat('done', 13), ...repeat('ahead', 7)]} size={14} />
        </span>
      </Specimen>
      <Specimen name="nothing yet">
        <span className="lib-inline">
          <ProgressDonut arcs={[]} />
          <ProgressDonut arcs={[]} size={14} />
        </span>
      </Specimen>
    </>
  )
}

/* ── a message's tasks ────────────────────────────────────────────────── */

const PROMO_PICKS = [
  { value: 'promo', label: 'promo weeks' },
  { value: 'normal', label: 'normal weeks' },
  { value: 'week-44', label: 'only week 44' },
]

/* A message whose work was split, and beside it its task list: three
   tasks, the fit open with what it asks, a line to write to it and its own
   tasks. The line under the message folds the list away and back. */
function TasksDemo() {
  const [listShown, setListShown] = React.useState(true)
  const [openId, setOpenId] = React.useState<string | null>('fit')
  const [answered, setAnswered] = React.useState<string | null>(null)
  const [log, setLog] = React.useState<string[]>([])
  const say = (entry: string) => setLog((l) => [...l.slice(-3), entry])
  /* One arc per task for the line under the message; the fit's own steps
     move on once it is answered. */
  const setArcs = arcs('done', 'working', 'working')
  const fitArcs = answered ? arcs('done', 'done', 'working') : arcs('done', 'working', 'ahead')

  return (
    <div className="lib-tasks" data-specimen="tasks">
      <div className="lib-tasks-messages">
        <MessageRow author={line(METRYON, 24)} name="Metryon" time="14:02">
          <MessageRow.Text>I split the Q4 view in three.</MessageRow.Text>
          <MessageRow.TaskLine
            arcs={setArcs}
            needsYou={!answered}
            count={3}
            aria-expanded={listShown}
            onOpen={() => setListShown((v) => !v)}
            data-specimen="task-line-count"
          />
        </MessageRow>
        <MessageRow author={<Glyph initial="o" label="Owen" size={24} />} name="Owen" time="14:05">
          <MessageRow.Text>Eiri, check the supplier notes against the filings.</MessageRow.Text>
        </MessageRow>
        <MessageRow author={line(EIRI, 24)} name="Eiri" time="14:06">
          <MessageRow.Text>I gave this to Tory.</MessageRow.Text>
          <MessageRow.TaskLine arcs={arcs('done', 'working')} who="Tory" onOpen={() => say('opened Tory’s task')} data-specimen="task-line-who" />
        </MessageRow>
      </div>
      {listShown ? (
        <div className="lib-tasks-pane">
          <TaskList openId={openId} onOpenChange={setOpenId} aria-label="tasks of the Q4 view" data-specimen="task-list">
            <TaskRow id="sales" arcs={repeat('done', 3)} name="pull Acme store sales" who="Tory">
              <TaskRow.Body>
                <TaskRow.Last>Three years of Acme store sales are in the vault.</TaskRow.Last>
              </TaskRow.Body>
            </TaskRow>
            <TaskRow id="fit" arcs={fitArcs} needsYou={!answered} name="fit the Q4 forecast" who="Metryon">
              <TaskRow.Body>
                <TaskRow.Last>The sales dip in weeks 44 to 46 every year.</TaskRow.Last>
                {answered ? (
                  <TaskRow.Last>Fitting with {answered} now.</TaskRow.Last>
                ) : (
                  <>
                    <NeedsYou
                      ground="bare"
                      aria-label="what the fit asks"
                      onSettle={(_, value) => {
                        const pick = PROMO_PICKS.find((p) => p.value === value)
                        setAnswered(pick?.label ?? value)
                        say(`answered ${value}`)
                      }}
                      onLater={() => say('set aside')}
                    >
                      <NeedsYou.Ask
                        id="fit-promo"
                        question="Should the fit treat weeks 44 to 46 as promo weeks?"
                        note="Sales dip in weeks 44 to 46 every year. As promo weeks, the fit leaves the dip out of the baseline."
                      >
                        <NeedsYou.Picks>
                          {PROMO_PICKS.map((p) => (
                            <NeedsYou.Pick key={p.value} value={p.value}>
                              {p.label}
                            </NeedsYou.Pick>
                          ))}
                          <NeedsYou.OwnAnswer />
                        </NeedsYou.Picks>
                      </NeedsYou.Ask>
                    </NeedsYou>
                  </>
                )}
                <TaskRow.Write placeholder="Write to Metryon" onSend={(text) => say(`wrote “${text}”`)} />
                <TaskRow.Own arcs={arcs('done', 'working', 'ahead')} onOpenRoom={() => say('opened the fit as a room')} />
              </TaskRow.Body>
            </TaskRow>
            <TaskRow id="outlook" arcs={arcs('working', 'ahead', 'ahead', 'ahead')} name="draft the supplier outlook" who="Antevon">
              <TaskRow.Body>
                <TaskRow.Last>Reading the May filings for the three suppliers.</TaskRow.Last>
                <TaskRow.Write placeholder="Write to Antevon" onSend={(text) => say(`wrote “${text}”`)} />
              </TaskRow.Body>
            </TaskRow>
          </TaskList>
          <span className="lib-readout" data-specimen="tasks-log">
            open {openId ?? 'none'}
            {log.length ? `, ${log.join(', ')}` : ''}
          </span>
        </div>
      ) : null}
    </div>
  )
}

/* A grouped list: what waits on you, what is working, and a done group of
   five folded to its count. */
function GroupedTasksDemo() {
  return (
    <TaskList grouped defaultOpenId={null} aria-label="tasks of the hokuei pilot" data-specimen="task-list-grouped">
      <TaskRow id="g-done-1" arcs={repeat('done', 2)} name="pull the supplier list" who="Tory" />
      <TaskRow id="g-work-1" arcs={arcs('done', 'working', 'ahead')} name="check the May filings" who="Tory" />
      <TaskRow id="g-needs" arcs={arcs('done', 'ahead')} needsYou name="pay for registry extracts" who="Antevon">
        <TaskRow.Body>
          <TaskRow.Last>Three extracts at ¥800 each would settle the dates.</TaskRow.Last>
        </TaskRow.Body>
      </TaskRow>
      <TaskRow id="g-done-2" arcs={repeat('done', 3)} name="summarise the Hokuei brief" who="Eiri" />
      <TaskRow id="g-work-2" arcs={arcs('done', 'failed', 'ahead')} name="match suppliers to filings" who="Metryon" />
      <TaskRow id="g-done-3" arcs={repeat('done', 1)} name="name the pilot room" who="Eiri" />
      <TaskRow id="g-done-4" arcs={repeat('done', 4)} name="draft the first outlook" who="Antevon" />
      <TaskRow id="g-done-5" arcs={repeat('done', 2)} name="file the notes" who="Tory" />
    </TaskList>
  )
}

/* ── versions of a reply ──────────────────────────────────────────────── */

const VERSIONS = [
  'Your notes from the August call say the promo runs in weeks 44 to 46.',
  'The August call notes put the promo in weeks 44 to 46; the May notes do not mention it.',
  'Weeks 44 to 46, from the August call. Nothing in the May notes contradicts it.',
]

function VersionsDemo() {
  const [count, setCount] = React.useState(2)
  const [value, setValue] = React.useState(2)
  return (
    <div className="lib-stack" data-specimen="versions">
      <MessageRow author={line(EIRI, 24)} name="Eiri" time="14:08">
        <MessageRow.Text data-specimen="versions-text">{VERSIONS[(value - 1) % VERSIONS.length]}</MessageRow.Text>
        <VersionSwitch
          count={count}
          value={value}
          onValueChange={setValue}
          onTryAgain={() => {
            const next = Math.min(count + 1, VERSIONS.length)
            setCount(next)
            setValue(next)
          }}
          data-specimen="version-switch"
        />
      </MessageRow>
    </div>
  )
}

/* ── settled asks ─────────────────────────────────────────────────────── */

function SettledDemo() {
  const [retried, setRetried] = React.useState(0)
  const [viewed, setViewed] = React.useState(false)
  return (
    <div className="lib-settled" data-specimen="settled">
      <SettledCard
        asker={line(METRYON)}
        question="Should the fit treat weeks 44 to 46 as promo weeks?"
        pick="promo weeks"
        state="answered"
        time="14:06"
        data-specimen="settled-answered"
      >
        <SettledCard.Detail onViewRequest={() => setViewed(true)}>
          Metryon marks weeks 44 to 46 as promo weeks in the Q4 fit and fits it again.
        </SettledCard.Detail>
      </SettledCard>
      <SettledCard asker={<Glyph initial="y" label="Yuki" size={18} guest />} question="Edit Acme store sales: three rows from Yuki" pick="approve" state="approved" time="11:20">
        <SettledCard.Detail>Three weekly rows for store 12 change; the old values stay in the ledger.</SettledCard.Detail>
      </SettledCard>
      <SettledCard asker={line(TORY)} question="Pull paid registry extracts at ¥800 each?" pick="allow once" state="allowed once" time="13:14" />
      <SettledCard asker={line(ANTEVON)} question="Connect Acme’s vault to the house?" pick="deny" state="denied" time="Yesterday" />
      <SettledCard
        asker={line(TORY)}
        question="Pull paid registry extracts at ¥800 each?"
        state="expired"
        time="9 Nov"
        onRetry={() => setRetried((n) => n + 1)}
        data-specimen="settled-expired"
      >
        <SettledCard.Missed>The extracts were not pulled; the outlook used last month’s filings.</SettledCard.Missed>
        <SettledCard.Detail onViewRequest={() => setViewed(true)}>
          Tory buys three registry extracts for the Hokuei suppliers, ¥2,400 in all.
        </SettledCard.Detail>
      </SettledCard>
      <span className="lib-readout" data-specimen="settled-log">
        {retried ? `asked again ${retried}` : 'not asked again'}
        {viewed ? ', full request viewed' : ''}
      </span>
    </div>
  )
}

/* ── the sections ─────────────────────────────────────────────────────── */

export function TaskSections() {
  return (
    <>
      <Section title="ProgressDonut">
        <DonutSpecimens />
      </Section>

      <Section title="Tasks: MessageRow.TaskLine, TaskList, TaskRow">
        <Specimen name="split work: the line under the message, the list beside it; the fit is open with its picks, a line to write and its own tasks" full>
          <TasksDemo />
        </Specimen>
        <Specimen name="grouped: needs you, working, then done folded to its count" full>
          <GroupedTasksDemo />
        </Specimen>
      </Section>

      <Section title="VersionSwitch">
        <Specimen name="under the newest reply: try again, then step through the versions" full>
          <VersionsDemo />
        </Specimen>
      </Section>

      <Section title="SettledCard">
        <Specimen name="answered, approved, allowed once, denied, expired with retry; what this does unfolds" full>
          <SettledDemo />
        </Specimen>
      </Section>
    </>
  )
}

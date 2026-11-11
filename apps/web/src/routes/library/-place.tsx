import * as React from 'react'
import {
  AppFrame,
  Composer,
  CrewStack,
  DayDivider,
  Figure,
  Icon,
  IconAction,
  Menu,
  MessageRow,
  PinMark,
  Place,
  PrimaryButton,
  ProgressDonut,
  RoomHead,
  RoomOutline,
  SafelightRoot,
  SceneSheet,
  SplitPane,
  TaskFlow,
  TaskList,
  TaskRow,
  TextField,
  ToneButton,
  VaultRow,
  Verb,
  WordDivider,
  formatAnswerTime,
  type DonutArc,
  type Theme,
} from '~/design-system'
import { CHART_TITLE, ChartCard } from './-cards'
import { Face, OWEN, YUKI, type Person } from './-faces'
import { HomeSidebar, MicroSidebarDemo } from './-frame'
import { ANTEVON, EIRI, METRYON, TORY, type Resident } from './-identity'
import { FIELD_SCENE, GALLERY_THEMES } from './-themes'

/* A room laid out with Place, the panes beside it (the outline, the tasks,
   one thing), and the screens outside a vault. The room is # acme-forecast
   of the gallery's cast; the person is Owen. */

/* ── the room ─────────────────────────────────────────────────────────── */

const PINNED_MESSAGE = 'Can we have the Q4 view by Friday?'
const FIT_ARCS: DonutArc[] = ['done', 'working', 'ahead']

type PaneState = null | { kind: 'outline' } | { kind: 'tasks' } | { kind: 'thing'; id: 'q4' | 'stores' }

interface Said {
  who: Resident | Person
  text: string
  time: string
}

function Crew() {
  return (
    <CrewStack aria-label="crew of # acme-forecast">
      <CrewStack.Member name="Owen, you" caption="here now">
        <Face who={OWEN} size={22} />
      </CrewStack.Member>
      <CrewStack.Member name="Yuki, a guest" caption="from Acme’s vault, reads and proposes">
        <Face who={YUKI} size={22} />
      </CrewStack.Member>
      <CrewStack.Member name="Metryon" caption="fitting the Q4 forecast for Acme">
        <Face who={METRYON} size={22} />
      </CrewStack.Member>
      <CrewStack.Member name="Tory" caption="pulled Acme store sales">
        <Face who={TORY} size={22} />
      </CrewStack.Member>
      <CrewStack.Member name="Antevon" caption="keeping the record">
        <Face who={ANTEVON} size={22} />
      </CrewStack.Member>
    </CrewStack>
  )
}

/* The room's talk: the pinned ask, the split into tasks, a thread, the
   chart; then what was sent and what arrived. */
function Talk({ said, marked, specimen, onOpenTask, onOpenThread }: { said: Said[]; marked: boolean; specimen: string; onOpenTask: (id: string) => void; onOpenThread: () => void }) {
  return (
    <>
      <DayDivider>Today</DayDivider>
      <MessageRow id={`${specimen}-pinned`} author={<Face who={YUKI} size={24} />} name="Yuki" time="13:50" marks={<PinMark />} marked={marked}>
        <MessageRow.Text>{PINNED_MESSAGE}</MessageRow.Text>
      </MessageRow>
      <MessageRow author={<Face who={METRYON} size={24} />} name="Metryon" time="14:02">
        <MessageRow.Text>I split the Q4 view in three.</MessageRow.Text>
        <TaskFlow aria-label="the tasks of this message" onOpen={onOpenTask}>
          <TaskFlow.Task id="pull" done who={<Face who={TORY} size={16} />}>
            pull Acme store sales
          </TaskFlow.Task>
          <TaskFlow.Task id="fit" arcs={FIT_ARCS} needsYou who={<Face who={METRYON} size={16} />}>
            fit the Q4 forecast
          </TaskFlow.Task>
          <TaskFlow.Task id="draft" arcs={['ahead']} who={<Face who={ANTEVON} size={16} />}>
            draft the supplier outlook
          </TaskFlow.Task>
        </TaskFlow>
      </MessageRow>
      <MessageRow author={<Face who={YUKI} size={24} />} name="Yuki" time="14:10">
        <MessageRow.Text>Which stores are in?</MessageRow.Text>
        <MessageRow.ThreadLine
          replies={2}
          lastReply="14:16"
          participants={
            <>
              <Face who={OWEN} size={18} />
              <Face who={METRYON} size={18} />
            </>
          }
          onClick={onOpenThread}
        />
      </MessageRow>
      <MessageRow author={<Face who={METRYON} size={24} />} name="Metryon" time="14:31" marks={<PinMark />}>
        <MessageRow.Text>First cut of the Q4 view. Your answer on weeks 44 to 46 decides which reading I keep.</MessageRow.Text>
        <ChartCard />
      </MessageRow>
      {said.map((m, i) => (
        <MessageRow key={i} author={<Face who={m.who} size={24} />} name={m.who.name} time={m.time} data-said="">
          <MessageRow.Text>{m.text}</MessageRow.Text>
        </MessageRow>
      ))}
    </>
  )
}

/* ── the panes ────────────────────────────────────────────────────────── */

function OutlinePane({ onClose, onOpen, specimen }: { onClose: () => void; onOpen: (id: string) => void; specimen: string }) {
  return (
    <SplitPane.Pane className="lib-list-pane" data-specimen={`${specimen}-outline`}>
      <SplitPane.Head title="Outline" onClose={onClose} />
      <RoomOutline aria-label="outline of # acme-forecast" onOpen={onOpen}>
        <RoomOutline.Group label="pinned">
          <RoomOutline.Row id="q4" mark={<Icon name="chart" />}>
            Q4 view
          </RoomOutline.Row>
          <RoomOutline.Row id="pinned-message" mark={<Icon name="pin" />} who="Yuki" time="13:50">
            {PINNED_MESSAGE}
          </RoomOutline.Row>
        </RoomOutline.Group>
        <RoomOutline.Group label="tasks">
          <RoomOutline.Row id="tasks" mark={<ProgressDonut arcs={FIT_ARCS} needsYou tooltip={false} />} who="Metryon" time="14:02">
            I split the Q4 view in three.
          </RoomOutline.Row>
        </RoomOutline.Group>
        <RoomOutline.Group label="threads">
          <RoomOutline.Row id="stores" mark={<Icon name="thread" />} who="Yuki" time="14:10">
            Which stores are in?
          </RoomOutline.Row>
        </RoomOutline.Group>
      </RoomOutline>
    </SplitPane.Pane>
  )
}

function TasksPane({ onClose, specimen }: { onClose: () => void; specimen: string }) {
  return (
    <SplitPane.Pane className="lib-list-pane" data-specimen={`${specimen}-tasks`}>
      <SplitPane.Head title="Tasks" onClose={onClose} />
      <TaskList defaultOpenId="pull" aria-label="tasks of the Q4 view">
        <TaskRow id="pull" arcs={['done', 'done']} name="pull Acme store sales" who={<Face who={TORY} size={18} />}>
          <TaskRow.Body>
            <TaskRow.Last>Three years of Acme store sales are in the vault.</TaskRow.Last>
          </TaskRow.Body>
        </TaskRow>
        <TaskRow id="fit" arcs={FIT_ARCS} needsYou name="fit the Q4 forecast" who={<Face who={METRYON} size={18} />}>
          <TaskRow.Body>
            <TaskRow.Last>The weekly sales are clean: three years, 214 stores. Weeks 44 to 46 dip every year.</TaskRow.Last>
            <TaskRow.Write placeholder="Write to Metryon" tools="always" onDictate={() => {}} />
          </TaskRow.Body>
        </TaskRow>
        <TaskRow id="draft" arcs={['ahead']} name="draft the supplier outlook" who={<Face who={ANTEVON} size={18} />}>
          <TaskRow.Body>
            <TaskRow.Last>Waits on the fit.</TaskRow.Last>
          </TaskRow.Body>
        </TaskRow>
      </TaskList>
    </SplitPane.Pane>
  )
}

const THREAD: Record<'q4' | 'stores', Said[]> = {
  q4: [],
  stores: [
    { who: OWEN, text: 'The twelve that close in November stay out.', time: '14:15' },
    { who: METRYON, text: 'Noted. Twelve of fourteen are in.', time: '14:16' },
  ],
}

function ThingPane({ id, onClose, specimen }: { id: 'q4' | 'stores'; onClose: () => void; specimen: string }) {
  const [thread, setThread] = React.useState<Said[]>(THREAD[id])
  return (
    <SplitPane.Thing
      key={id}
      title={id === 'q4' ? CHART_TITLE : 'Which stores are in?'}
      onClose={onClose}
      onSend={(text) => setThread((t) => [...t, { who: OWEN, text, time: formatAnswerTime(new Date()) }])}
      writeBox={{
        tools: 'always',
        onDictate: () => {},
        add: (
          <Composer.Add label="Add to the message">
            <Menu.Item icon={<Icon name="clip" />}>a file</Menu.Item>
            <Menu.Item icon={<Icon name="images" />}>a picture</Menu.Item>
          </Composer.Add>
        ),
      }}
      data-specimen={`${specimen}-thing`}
      thread={thread.map((m, i) => (
        <MessageRow key={i} author={<Face who={m.who} size={24} />} name={m.who.name} time={m.time}>
          <MessageRow.Text>{m.text}</MessageRow.Text>
        </MessageRow>
      ))}
    >
      {/* The chart card bare carries its own note under it. */}
      {id === 'q4' ? (
        <ChartCard bare />
      ) : (
        <p className="lib-thing-origin">
          <Face who={YUKI} size={18} />
          Yuki asked in # acme-forecast <Figure>14:10</Figure>
        </p>
      )}
    </SplitPane.Thing>
  )
}

/* ── the place in a frame ─────────────────────────────────────────────── */

/* The frame at a set size with the room built from Place: the head line
   (RoomHead with no tabs, the outline action at the right), the body that
   ends at the bottom, the write box. The outline opens in a list pane;
   its rows open the tasks, one thing, or go to the pinned message.
   `a message arrives` adds one at the end of the body. */
function PlaceDemo({ width, height, startPane, specimen, caption }: { width: number; height: number; startPane: PaneState; specimen: string; caption: string }) {
  const [current, setCurrent] = React.useState('home')
  const [sidebarOpen, setSidebarOpen] = React.useState(true)
  const [pane, setPane] = React.useState<PaneState>(startPane)
  const [said, setSaid] = React.useState<Said[]>([])
  const [marked, setMarked] = React.useState(0)
  const bodyRef = React.useRef<HTMLDivElement | null>(null)
  React.useEffect(() => {
    if (!marked) return
    const timer = setTimeout(() => setMarked(0), 1800)
    return () => clearTimeout(timer)
  }, [marked])

  const goToPinned = () => {
    setMarked((n) => n + 1)
    bodyRef.current?.querySelector(`#${specimen}-pinned`)?.scrollIntoView({ block: 'center' })
  }
  const openFromOutline = (id: string) => {
    if (id === 'q4' || id === 'stores') setPane({ kind: 'thing', id })
    else if (id === 'tasks') setPane({ kind: 'tasks' })
    else if (id === 'pinned-message') goToPinned()
  }
  const close = () => setPane(null)

  const room = (
    <Place data-specimen={`${specimen}-place`}>
      <Place.Head>
        <RoomHead
          title="acme-forecast"
          icon={<Icon name="hash" />}
          pins="none"
          crew={<Crew />}
          outlineOpen={pane?.kind === 'outline'}
          onOpenOutline={() => setPane(pane?.kind === 'outline' ? null : { kind: 'outline' })}
        />
      </Place.Head>
      <Place.Body ref={bodyRef} data-specimen={`${specimen}-body`}>
        <Talk said={said} marked={marked > 0} specimen={specimen} onOpenTask={() => setPane({ kind: 'tasks' })} onOpenThread={() => setPane({ kind: 'thing', id: 'stores' })} />
      </Place.Body>
      <Place.Foot>
        <Composer
          placeholder="Write to acme-forecast"
          persona={<Composer.Persona initial="o" note="You write as Owen. Saved in Antevon’s vault." aria-label="Owen" />}
          onVoice={() => {}}
          onDictate={() => {}}
          onSend={(text) => setSaid((s) => [...s, { who: OWEN, text, time: formatAnswerTime(new Date()) }])}
        >
          <Composer.Add label="Add to the message">
            <Menu.Item icon={<Icon name="clip" />}>a file</Menu.Item>
            <Menu.Item icon={<Icon name="tool" />}>model and effort</Menu.Item>
          </Composer.Add>
        </Composer>
      </Place.Foot>
    </Place>
  )

  return (
    <figure className="lib-frame-specimen">
      <div className="lib-frame-scroller">
        <SafelightRoot theme={GALLERY_THEMES[0]} className="lib-beside-root" style={{ width, height }}>
          <AppFrame
            className="lib-frame"
            data-specimen={specimen}
            microSidebar={<MicroSidebarDemo current={current} onCurrent={setCurrent} />}
            sidebar={<HomeSidebar specimen={`${specimen}-home`} defaultCurrent="acme-forecast" faces />}
            sidebarOpen={sidebarOpen}
            onSidebarOpenChange={setSidebarOpen}
          >
            <SplitPane
              pane={pane?.kind === 'thing' ? 'thing' : 'list'}
              className="lib-beside-split"
              style={pane ? undefined : { gridTemplateColumns: 'minmax(0, 1fr)' }}
              data-specimen={`${specimen}-split`}
            >
              <SplitPane.Pane className="lib-beside-room">{room}</SplitPane.Pane>
              {pane ? <SplitPane.Handle aria-label="resize the pane" /> : null}
              {pane?.kind === 'outline' ? <OutlinePane onClose={close} onOpen={openFromOutline} specimen={specimen} /> : null}
              {pane?.kind === 'tasks' ? <TasksPane onClose={close} specimen={specimen} /> : null}
              {pane?.kind === 'thing' ? <ThingPane id={pane.id} onClose={close} specimen={specimen} /> : null}
            </SplitPane>
          </AppFrame>
        </SafelightRoot>
      </div>
      <figcaption className="lib-field-caption lib-place-caption">{caption}</figcaption>
      <p className="lib-field-readout lib-place-caption" data-specimen={`${specimen}-state`}>
        pane {pane ? (pane.kind === 'thing' ? `thing ${pane.id}` : pane.kind) : 'closed'}, messages added {said.length}
        <button
          type="button"
          className="lib-pick lib-field-pick"
          data-specimen={`${specimen}-arrive`}
          onClick={() => setSaid((s) => [...s, { who: METRYON, text: `Fitting week ${44 + (s.length % 3)} again with the new stores.`, time: formatAnswerTime(new Date()) }])}
        >
          a message arrives
        </button>
        {pane ? null : (
          <button type="button" className="lib-pick lib-field-pick" onClick={() => setPane({ kind: 'outline' })}>
            open the outline
          </button>
        )}
      </p>
    </figure>
  )
}

export function PlaceSection() {
  return (
    <section className="lib-field-section" aria-labelledby="lib-place">
      <h2 id="lib-place" className="lib-field-head">
        Place, RoomOutline: a room laid out in the work area, and the panes beside it
      </h2>
      <PlaceDemo
        width={1440}
        height={900}
        startPane={null}
        specimen="place-1440"
        caption="1440 wide: Place.Head holds the room’s head line, Place.Body ends at the bottom and keeps the newest in view while you are at the end (press a message arrives); scroll up and your place holds; Place.Foot holds the write box"
      />
      <PlaceDemo
        width={1440}
        height={900}
        startPane={{ kind: 'outline' }}
        specimen="place-1440-outline"
        caption="1440 wide, the outline beside the room: pinned, tasks, threads; a row opens its thing, the tasks or the thread, or goes to the pinned message"
      />
      <PlaceDemo
        width={1100}
        height={800}
        startPane={{ kind: 'outline' }}
        specimen="place-1100-outline"
        caption="1100 wide: the work area cannot hold the column and a 340 px list, so the outline lies over the room from the right edge; the room keeps its column"
      />
      <PlaceDemo
        width={1100}
        height={800}
        startPane={{ kind: 'thing', id: 'q4' }}
        specimen="place-1100-thing"
        caption="1100 wide, one thing: it lies over the room too; its write box carries add, dictation and send"
      />
    </section>
  )
}

/* ── outside a vault ──────────────────────────────────────────────────── */

interface VaultFixture {
  id: string
  name: string
  runs: string
  theme: Theme
  waiting: number
}

const VAULTS: VaultFixture[] = [
  { id: 'owen', name: 'owen', runs: 'this Mac and two of your machines', theme: FIELD_SCENE, waiting: 2 },
  { id: 'antevon', name: 'antevon', runs: 'Oneiron Cloud', theme: GALLERY_THEMES[2], waiting: 3 },
  { id: 'acme', name: 'acme', runs: 'guest · Oneiron Cloud', theme: GALLERY_THEMES[1], waiting: 0 },
]

/* A neutral stand-in for a sign-in provider's own mark. */
const PROVIDER_MARK = <span className="lib-provider-disc" />

function SignInSheet({ onLog }: { onLog: (line: string) => void }) {
  const [email, setEmail] = React.useState('')
  return (
    <SceneSheet brand brandAlign="center" aria-label="sign in" data-specimen="outside-sign-in-sheet">
      <div className="lib-sign-in">
        <ToneButton mark={PROVIDER_MARK} onClick={() => onLog('continues with the work account')}>
          Continue with a work account
        </ToneButton>
        <ToneButton mark={PROVIDER_MARK} onClick={() => onLog('continues with the personal account')}>
          Continue with a personal account
        </ToneButton>
        <WordDivider className="lib-sign-in-or" />
        <form
          className="lib-sign-in-email"
          onSubmit={(event) => {
            event.preventDefault()
            onLog(email ? `continues with ${email}` : 'asks for an email address')
          }}
        >
          <TextField
            type="email"
            name="email"
            aria-label="Email address"
            placeholder="Email address"
            autoComplete="email"
            value={email}
            onValueChange={setEmail}
            data-specimen="outside-email"
          />
          <PrimaryButton type="submit" className="lib-wide-button">
            Continue with email
          </PrimaryButton>
        </form>
        <Verb className="lib-sign-in-passkey" onClick={() => onLog('signs in with a passkey')}>
          sign in with a passkey
        </Verb>
      </div>
    </SceneSheet>
  )
}

function VaultsSheet({ onShow, onLog }: { onShow: (theme: Theme | null) => void; onLog: (line: string) => void }) {
  return (
    <SceneSheet brand brandAlign="start" width={620} aria-labelledby="lib-vaults-title" data-specimen="outside-vaults-sheet">
      <h1 id="lib-vaults-title" className="lib-vaults-title">
        Your vaults
      </h1>
      <ul className="lib-vault-list" onPointerLeave={() => onShow(null)}>
        {VAULTS.map((v) => (
          <li key={v.id}>
            <VaultRow
              theme={v.theme}
              name={v.name}
              runs={v.runs}
              waiting={v.waiting}
              onPointerEnter={() => onShow(v.theme)}
              onFocus={() => onShow(v.theme)}
              onBlur={() => onShow(null)}
              onClick={() => onLog(`opens ${v.name}`)}
              data-specimen={`outside-vault-${v.id}`}
            />
          </li>
        ))}
      </ul>
      <Verb className="lib-vault-new" onClick={() => onLog('makes a new vault')}>
        <Icon name="plus" />
        new vault
      </Verb>
      <footer className="lib-vaults-foot">
        <span className="lib-vaults-who">
          <Face who={OWEN} size={20} />
          Owen
        </span>
        <span className="lib-vaults-verbs">
          <Verb onClick={() => onLog('opens my network')}>my network</Verb>
          <Verb onClick={() => onLog('opens plan and payment')}>plan and payment</Verb>
          <Verb onClick={() => onLog('signs out')}>sign out</Verb>
        </span>
      </footer>
    </SceneSheet>
  )
}

/* One screen outside a vault at 1440 x 900, on the gallery's scene. On
   the vaults sheet, resting on a vault shows its theme behind the sheet. */
function OutsideDemo({ screen, specimen, caption }: { screen: 'sign in' | 'vaults'; specimen: string; caption: string }) {
  const [shown, setShown] = React.useState<Theme | null>(null)
  const [log, setLog] = React.useState('')
  return (
    <figure className="lib-frame-specimen">
      <div className="lib-frame-scroller">
        <SafelightRoot theme={shown ?? FIELD_SCENE} className="lib-outside-root" data-specimen={specimen}>
          {screen === 'sign in' ? <SignInSheet onLog={setLog} /> : <VaultsSheet onShow={setShown} onLog={setLog} />}
        </SafelightRoot>
      </div>
      <figcaption className="lib-field-caption lib-place-caption">{caption}</figcaption>
      <p className="lib-field-readout lib-place-caption" data-specimen={`${specimen}-state`}>
        theme {(shown ?? FIELD_SCENE).label}
        {log ? `, ${log}` : ''}
      </p>
    </figure>
  )
}

export function OutsideSection() {
  return (
    <section className="lib-field-section" aria-labelledby="lib-outside">
      <h2 id="lib-outside" className="lib-field-head">
        outside a vault: SceneSheet, ToneButton, WordDivider, TextField, VaultRow
      </h2>
      <OutsideDemo
        screen="sign in"
        specimen="outside-sign-in"
        caption="sign in: one sheet centred on the scene; two tone buttons with a provider’s mark, or, the email field and the one filled button, a passkey as a word"
      />
      <OutsideDemo
        screen="vaults"
        specimen="outside-vaults"
        caption="your vaults: each vault’s picture, name, where it runs and what waits; rest on a vault and its theme shows behind the sheet"
      />
    </section>
  )
}

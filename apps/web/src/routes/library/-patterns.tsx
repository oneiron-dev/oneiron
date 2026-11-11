import * as React from 'react'
import {
  ClaimText,
  Composer,
  ConnectionRow,
  CrewStack,
  DayDivider,
  FileGroup,
  FileRow,
  Figure,
  Glyph,
  HoverBar,
  Icon,
  IconAction,
  InfoMark,
  LedgerTable,
  Menu,
  MessageRow,
  NeedsYou,
  OutsideLine,
  Popover,
  Portrait,
  RunFoot,
  SplitPane,
  StepsBar,
  Verb,
  formatElapsed,
  type ComposerPersonaKind,
  type NeedsYouAnswerRecord,
  type NeedsYouAnswers,
  type ComposerTools,
  type RunSubState,
  type Step,
} from '~/design-system'
import { Section, Specimen } from './-gallery-frame'

/* Pattern sections of the /library gallery: each demo works, on fixture
   data from the app's cast. */

/* ── needs you ────────────────────────────────────────────────────────── */

const PROMO_NOTE = 'Sales dip in weeks 44 to 46 every year. As promo weeks, the fit leaves the dip out of the baseline.'
const EXTRACTS_NOTE = 'Buys one extract for each of the three Kobe suppliers at ¥800. Paid from the house card. The files land in # the house.'

/* An answer given earlier this morning: the record line, no undo. */
const STORES_ANSWER: NeedsYouAnswerRecord = { value: 'drop', word: 'drop them', mark: 'pick', time: '09:14' }

/* Two rooms' asks: a pick ask and an answered one, a yes-or-no ask with a
   figure and one set aside (held here, controlled). */
function AsksBlock({ answers, specimen }: { answers: NeedsYouAnswers; specimen: string }) {
  const [round, setRound] = React.useState(0)
  const [log, setLog] = React.useState<string[]>([])
  const [aside, setAside] = React.useState<string[]>(['join'])
  const [waiting, setWaiting] = React.useState(2)
  const say = (line: string) => setLog((l) => [...l.slice(-2), line])
  return (
    <div className="lib-stack lib-asks" data-specimen={specimen}>
      <NeedsYou
        key={round}
        answers={answers}
        aria-label="needs you, from two rooms"
        onAnswerChange={(id, answer) => {
          setWaiting((n) => n + (answer ? -1 : 1))
          say(answer ? `${id}: ${answer.word}` : `${id}: undone`)
        }}
        onSettle={(id, value) => say(`${id} stands: ${value}`)}
        onLater={(id) => say(`${id}: set aside`)}
      >
        <NeedsYou.Group room="acme-forecast">
          <NeedsYou.Ask
            id="promo"
            asker={<Glyph glyph="ruler" label="Metryon" size={20} />}
            question="Should the fit treat weeks 44 to 46 as promo weeks?"
            note={PROMO_NOTE}
            onOpen={() => say('promo: opened beside the room')}
          >
            <NeedsYou.Picks>
              <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
              <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
              <NeedsYou.Pick value="week-44">only week 44</NeedsYou.Pick>
              <NeedsYou.OwnAnswer />
            </NeedsYou.Picks>
          </NeedsYou.Ask>
          <NeedsYou.Ask
            id="stores"
            asker={<Glyph initial="y" label="Yuki" size={20} guest />}
            question="Edit Acme store sales: drop the 12 stores that close in November?"
            note="Yuki proposes the edit from Acme’s vault. The old rows stay in the ledger."
            defaultAnswer={STORES_ANSWER}
          >
            <NeedsYou.Picks>
              <NeedsYou.Pick value="drop" word="drop them">
                drop them
              </NeedsYou.Pick>
              <NeedsYou.Pick value="keep" word="keep them">
                keep them
              </NeedsYou.Pick>
              <NeedsYou.OwnAnswer />
            </NeedsYou.Picks>
          </NeedsYou.Ask>
        </NeedsYou.Group>
        <NeedsYou.Group room="the house">
          <NeedsYou.Ask
            id="extracts"
            asker={<Glyph glyph="owl" label="Tory" size={20} />}
            question="Pull three paid registry extracts?"
            note={EXTRACTS_NOTE}
            onOpen={() => say('extracts: opened beside the room')}
          >
            <NeedsYou.YesNo figure="¥2,400" />
          </NeedsYou.Ask>
          <NeedsYou.Ask
            id="join"
            asker={<Glyph glyph="wing" label="Eiri" size={20} />}
            question="Join # hokuei pilot for up to a tenth of my week?"
            note="Reads the Hokuei email map, drafts two openers for the COO, and stops at a tenth of the week."
            setAside={aside.includes('join')}
            onSetAsideChange={(on) => setAside((l) => (on ? [...l, 'join'] : l.filter((x) => x !== 'join')))}
          >
            <NeedsYou.YesNo yesWord="let in" noWord="not let in" yesLabel="Let in" noLabel="No" />
          </NeedsYou.Ask>
        </NeedsYou.Group>
      </NeedsYou>
      <span className="lib-readout">
        <span data-specimen={`${specimen}-log`}>{log.length ? log.join(', ') : 'Nothing answered yet.'}</span>
        <span>
          waiting <Figure data-specimen={`${specimen}-waiting`}>{waiting}</Figure>
        </span>
        <span data-specimen={`${specimen}-aside`}>set aside: {aside.join(', ') || 'none'}</span>
        <Verb
          onClick={() => {
            setAside(['join'])
            setWaiting(2)
            setLog([])
            setRound((r) => r + 1)
          }}
        >
          bring them back
        </Verb>
      </span>
    </div>
  )
}

/* ── the information mark ─────────────────────────────────────────────── */

const STORES_NOTE = 'Metryon built this list from Acme store sales: 214 stores, sold through week 45. Twelve close in November.'

/* A block with its mark at the right end of its first line. Rest on the
   mark for the note; press it and the caller opens the block beside the
   room (here the readout counts it). */
function InfoBlock({ specimen, open }: { specimen: string; open?: boolean }) {
  const [opened, setOpened] = React.useState(0)
  return (
    <div className="lib-stack">
      <div className="lib-info-block" data-info-block="" data-specimen={specimen}>
        <span className="lib-info-title">Stores in the pilot</span>
        <InfoMark note={STORES_NOTE} defaultOpen={open} onOpen={() => setOpened((n) => n + 1)} />
      </div>
      <span className="lib-readout" data-specimen={`${specimen}-log`}>
        {opened ? `opened beside the room ${opened === 1 ? 'once' : `${opened} times`}` : 'Press the mark to open the block beside the room.'}
      </span>
    </div>
  )
}

/* ── the column ───────────────────────────────────────────────────────── */

/* Three messages and a card in the messages column: the rows start at the
   left edge; the text, the card and the write box share one width. */
function ColumnDemo() {
  const [marked, setMarked] = React.useState(false)
  React.useEffect(() => {
    if (!marked) return
    const timer = setTimeout(() => setMarked(false), 1800)
    return () => clearTimeout(timer)
  }, [marked])
  return (
    <div className="lib-stack">
      <div className="lib-messages lib-column" data-specimen="column">
        <DayDivider>Today</DayDivider>
        <MessageRow
          author={<Glyph initial="y" label="Yuki" size={24} guest />}
          name="Yuki"
          time="13:50"
          marked={marked}
          marks={
            <span title="Pinned in this room" className="lib-pin-mark">
              <Icon name="pin" size={14} />
            </span>
          }
          data-specimen="column-pinned"
        >
          <MessageRow.Text>Can we have the Q4 view by Friday?</MessageRow.Text>
        </MessageRow>
        <MessageRow author={<Glyph glyph="ruler" label="Metryon" size={24} />} name="Metryon" time="14:02">
          <MessageRow.Text>Before I fit the quarter, one answer from you. The rest of the view waits on it.</MessageRow.Text>
          <NeedsYou aria-label="needs you" className="lib-column-card">
            <NeedsYou.Group room="acme-forecast">
              <NeedsYou.Ask
                id="column-promo"
                asker={<Glyph glyph="ruler" label="Metryon" size={20} />}
                question="Should the fit treat weeks 44 to 46 as promo weeks?"
                note={PROMO_NOTE}
              >
                <NeedsYou.Picks>
                  <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
                  <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
                  <NeedsYou.Pick value="week-44">only week 44</NeedsYou.Pick>
                  <NeedsYou.OwnAnswer />
                </NeedsYou.Picks>
              </NeedsYou.Ask>
            </NeedsYou.Group>
          </NeedsYou>
        </MessageRow>
        <MessageRow author={<Glyph initial="o" label="Owen" size={24} />} name="Owen" time="14:10">
          <MessageRow.Text>
            Keep the promo weeks for now. When the fit is in, put week 44 on its own line as well, so Yuki can see what the dip costs the
            quarter before Friday, and keep last year’s weeks beside it for the same stores.
          </MessageRow.Text>
        </MessageRow>
      </div>
      <Composer
        placeholder="Write to acme-forecast"
        persona={<Composer.Persona initial="o" note="You write as Owen. Saved in Antevon’s vault." aria-label="Owen" />}
        onVoice={() => {}}
        onDictate={() => {}}
        data-specimen="column-write"
      >
        {composerAddMenu()}
      </Composer>
      <span className="lib-readout">
        <Verb onClick={() => setMarked(true)}>go to the pinned message</Verb>
        <span data-specimen="column-marked">{marked ? 'marked' : 'not marked'}</span>
      </span>
    </div>
  )
}

/* ── messages ─────────────────────────────────────────────────────────── */

function MessageActions({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  return (
    <HoverBar aria-label="message actions">
      <IconAction label="Add a reaction" tooltipSide="top">
        <Icon name="smile" />
      </IconAction>
      <IconAction label="Reply in the thread" tooltipSide="top">
        <Icon name="thread" />
      </IconAction>
      <IconAction label="Forward" tooltipSide="top">
        <Icon name="forward" />
      </IconAction>
      <IconAction label="Save for later" tooltipSide="top" aria-pressed={saved} onClick={onSave}>
        <Icon name="save" />
      </IconAction>
      <Menu>
        <Menu.Trigger asChild>
          <IconAction label="More" tooltipSide="top">
            <Icon name="more" />
          </IconAction>
        </Menu.Trigger>
        <Menu.Content align="end">
          <Menu.Item icon={<Icon name="reply" />}>quote in a reply</Menu.Item>
          <Menu.Item icon={<Icon name="link" />}>copy the link</Menu.Item>
        </Menu.Content>
      </Menu>
    </HoverBar>
  )
}

interface ReactionState {
  emoji: string
  count: number
  mine: boolean
  who: string
}

function useReactions(initial: ReactionState[]) {
  const [list, setList] = React.useState(initial)
  const toggle = (emoji: string) =>
    setList((l) => {
      const r = l.find((x) => x.emoji === emoji)
      if (!r) return [...l, { emoji, count: 1, mine: true, who: 'Owen' }]
      const count = r.count + (r.mine ? -1 : 1)
      if (!count) return l.filter((x) => x !== r)
      const others = r.who.split(', ').filter((w) => w !== 'Owen')
      const who = (r.mine ? others : ['Owen', ...others]).join(', ')
      return l.map((x) => (x === r ? { ...x, count, mine: !x.mine, who } : x))
    })
  return [list, toggle] as const
}

function MessagesDemo() {
  const [saved, setSaved] = React.useState<string[]>([])
  const save = (id: string) => () => setSaved((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))
  const [reactions, toggle] = useReactions([
    { emoji: '👍', count: 2, mine: true, who: 'Owen, Yuki' },
    { emoji: '✅', count: 1, mine: false, who: 'Tory' },
  ])
  return (
    <div className="lib-messages" data-specimen="messages">
      <DayDivider>Yesterday</DayDivider>
      <MessageRow
        author={<Glyph glyph="ruler" label="Metryon" size={24} />}
        name="Metryon"
        time="Yesterday at 16:40"
      >
        <MessageRow.Text>The sales pull is done: three years of Acme store sales.</MessageRow.Text>
        <MessageRow.Attachments>
          <MessageRow.Attachment icon="sheet">Acme store sales</MessageRow.Attachment>
          <MessageRow.Attachment icon="note">week 44 dips</MessageRow.Attachment>
        </MessageRow.Attachments>
        <MessageActions saved={saved.includes('m1')} onSave={save('m1')} />
      </MessageRow>
      <DayDivider>Today</DayDivider>
      <MessageRow author={<Glyph initial="o" label="Owen" size={24} />} name="Owen" time="46 min ago" data-specimen="message-reactions">
        <MessageRow.Text>Eiri, do my notes say anything about Acme’s promo calendar?</MessageRow.Text>
        <MessageRow.Reactions onAdd={() => toggle('👀')}>
          {reactions.map((r) => (
            <MessageRow.Reaction key={r.emoji} emoji={r.emoji} count={r.count} pressed={r.mine} who={r.who} onClick={() => toggle(r.emoji)} />
          ))}
        </MessageRow.Reactions>
        <MessageActions saved={saved.includes('m2')} onSave={save('m2')} />
      </MessageRow>
      <MessageRow author={<Glyph glyph="wing" label="Eiri" size={24} guest />} name="Eiri" time="44 min ago" provisional>
        <MessageRow.Fold summary="from Owen’s vault">
          <span>Answered from Owen’s personal vault.</span>
          <span>Nothing was copied into this vault.</span>
          <span>It stays provisional until a member accepts it.</span>
        </MessageRow.Fold>
        <MessageRow.Text>Your notes from the August call say the promo runs in weeks 44 to 46.</MessageRow.Text>
        <MessageActions saved={saved.includes('m3')} onSave={save('m3')} />
      </MessageRow>
      <MessageRow author={<Glyph glyph="ruler" label="Metryon" size={24} />} name="Metryon" time="31 min ago" data-specimen="message-thread">
        <MessageRow.Text>Starting on the Q4 view Yuki asked for.</MessageRow.Text>
        <MessageRow.ThreadLine
          replies={3}
          lastReply="6 min ago"
          unread
          participants={
            <>
              <Glyph glyph="ruler" label="Metryon" size={18} />
              <Glyph initial="o" label="Owen" size={18} />
            </>
          }
        />
        <MessageActions saved={saved.includes('m4')} onSave={save('m4')} />
      </MessageRow>
    </div>
  )
}

/* ── the run foot ─────────────────────────────────────────────────────── */

const SUB_STATES: RunSubState[] = ['thinking', 'calling a tool', 'writing', 'waiting on you']
const CALLS = [
  { name: 'read_sales', by: 'Metryon', duration: 38 },
  { name: 'read_calendar', by: 'Metryon', duration: 12 },
  { name: 'summarise_claims', by: 'Metryon', duration: 96 },
]

/* The gallery plays the run: elapsed comes from its own clock, never the
   component's. */
function RunFootDemo() {
  const [startedAt, setStartedAt] = React.useState(() => Date.now() - 252_000)
  const [now, setNow] = React.useState(startedAt + 252_000)
  const [stoppedAt, setStoppedAt] = React.useState<number | null>(null)
  React.useEffect(() => {
    if (stoppedAt !== null) return
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [stoppedAt])
  const elapsed = Math.floor(((stoppedAt ?? now) - startedAt) / 1000)
  const calls = Math.min(3, 1 + Math.floor(elapsed / 120))
  const subState = SUB_STATES[Math.floor(elapsed / 20) % 3]
  return (
    <div className="lib-stack" data-specimen="run-foot">
      {stoppedAt === null ? (
        <RunFoot
          status="working"
          who={<Glyph glyph="ruler" label="Metryon" size={18} />}
          subState={subState}
          elapsed={elapsed}
          toolCalls={calls}
          onInterrupt={() => setStoppedAt(Date.now())}
        />
      ) : (
        <RunFoot status="done" summary={`stopped by you after ${formatElapsed(elapsed)}, ${calls} tool ${calls === 1 ? 'call' : 'calls'}`}>
          {CALLS.slice(0, calls).map((c) => (
            <RunFoot.Call key={c.name} name={c.name} by={c.by} duration={c.duration} />
          ))}
        </RunFoot>
      )}
      <span className="lib-readout">
        <Verb
          onClick={() => {
            const t = Date.now()
            setStartedAt(t - 252_000)
            setNow(t)
            setStoppedAt(null)
          }}
        >
          run again
        </Verb>
      </span>
    </div>
  )
}

/* ── the crew ─────────────────────────────────────────────────────────── */

function CrewPopoverHead({ glyph, name, line }: { glyph: 'ruler' | 'owl'; name: string; line: string }) {
  return (
    <div className="lib-crew">
      <Portrait glyph={glyph} label={name} size="stack" />
      <div className="lib-crew-who">
        <span className="lib-crew-name">{name}</span>
        <span className="lib-crew-line">{line}</span>
      </div>
    </div>
  )
}

function CrewDemo({ open }: { open?: boolean }) {
  const [invites, setInvites] = React.useState(0)
  return (
    <div className="lib-stack">
      <CrewStack
        aria-label="crew of # acme-forecast"
        data-specimen={open ? undefined : 'crew'}
        onInvite={() => setInvites((n) => n + 1)}
      >
        <CrewStack.Member name="Owen, you" caption="here now">
          <Glyph initial="o" label="Owen" state="idle" />
        </CrewStack.Member>
        <CrewStack.Member name="Yuki, a guest" caption="from Acme’s vault, reads and proposes">
          <Glyph initial="y" label="Yuki" guest />
        </CrewStack.Member>
        <Popover defaultOpen={open}>
          <Popover.Trigger asChild>
            <CrewStack.Member name="Metryon" caption="fitting the Q4 forecast for Acme">
              <Glyph glyph="ruler" label="Metryon" size={18} state="working" />
            </CrewStack.Member>
          </Popover.Trigger>
          <Popover.Content align="end" offset={10} className="lib-crew-pop" aria-label="Metryon">
            <CrewPopoverHead glyph="ruler" name="Metryon" line="fitting the Q4 forecast for Acme" />
            <NeedsYou ground="bare" aria-label="Metryon’s asks">
              <NeedsYou.Ask
                id="pop-promo"
                asker={<Glyph glyph="ruler" label="Metryon" size={20} />}
                question="Should the fit treat weeks 44 to 46 as promo weeks?"
                note={PROMO_NOTE}
              >
                <NeedsYou.Picks>
                  <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
                  <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
                  <NeedsYou.OwnAnswer />
                </NeedsYou.Picks>
              </NeedsYou.Ask>
              <NeedsYou.Ask id="pop-band" asker={<Glyph glyph="ruler" label="Metryon" size={20} />} question="How should I split the Q4 band?">
                <NeedsYou.Picks>
                  <NeedsYou.Pick value="supplier">by supplier</NeedsYou.Pick>
                  <NeedsYou.Pick value="region">by region</NeedsYou.Pick>
                </NeedsYou.Picks>
              </NeedsYou.Ask>
            </NeedsYou>
          </Popover.Content>
        </Popover>
        <CrewStack.Member name="Tory" caption="checking the May filings">
          <Glyph glyph="owl" label="Tory" size={18} state="waiting" />
        </CrewStack.Member>
        <CrewStack.Member name="Antevon" caption="keeping the record">
          <Glyph glyph="laurel" label="Antevon" size={18} state="idle" />
        </CrewStack.Member>
        <CrewStack.Member name="Eiri, a guest" caption="from Owen’s personal vault">
          <Glyph glyph="wing" label="Eiri" size={18} guest />
        </CrewStack.Member>
        <CrewStack.List>
          <CrewStack.ListRow glyph={<Glyph initial="o" label="Owen" />} href="#owen">
            Owen (you)
          </CrewStack.ListRow>
          <CrewStack.ListRow glyph={<Glyph initial="y" label="Yuki" guest />} href="#yuki">
            Yuki
          </CrewStack.ListRow>
          <CrewStack.ListRow glyph={<Glyph glyph="ruler" label="Metryon" />} href="#metryon">
            Metryon
          </CrewStack.ListRow>
          <CrewStack.ListRow glyph={<Glyph glyph="owl" label="Tory" />} href="#tory">
            Tory
          </CrewStack.ListRow>
          <CrewStack.ListRow glyph={<Glyph glyph="laurel" label="Antevon" />} href="#antevon">
            Antevon
          </CrewStack.ListRow>
          <CrewStack.ListRow glyph={<Glyph glyph="wing" label="Eiri" guest />} href="#eiri">
            Eiri
          </CrewStack.ListRow>
        </CrewStack.List>
      </CrewStack>
      {invites ? <span className="lib-readout">The invite opens here: a resident, or a person as a guest.</span> : null}
    </div>
  )
}

/* ── the split ────────────────────────────────────────────────────────── */

function SplitDemo() {
  const [value, setValue] = React.useState(0.5)
  const [threadOpen, setThreadOpen] = React.useState(true)
  const [replies, setReplies] = React.useState<string[]>([])
  const [log, setLog] = React.useState('')
  const reopenRef = React.useRef<HTMLButtonElement | null>(null)
  const close = () => {
    setThreadOpen(false)
    setLog('thread closed')
    requestAnimationFrame(() => reopenRef.current?.focus())
  }
  const room = (
    <>
      <span className="lib-t-section">acme-forecast</span>
      <span className="lib-t-say">Starting on the Q4 view Yuki asked for.</span>
    </>
  )
  return (
    <div className="lib-stack lib-split-wrap">
      {threadOpen ? (
        <SplitPane
          className="lib-split"
          defaultValue={0.5}
          onValueChange={setValue}
          min={0.25}
          max={0.8}
          storageKey="sl-library-split"
          data-specimen="split"
        >
          <SplitPane.Pane className="lib-split-pane">{room}</SplitPane.Pane>
          <SplitPane.Handle aria-label="resize the thread pane" />
          <SplitPane.Pane className="lib-split-pane lib-thread-pane" data-specimen="thread-pane">
            <SplitPane.Head
              title="Q4 forecast for Acme"
              onClose={close}
              actions={
                <>
                  <IconAction label="Outline" caption="the thread's branches">
                    <Icon name="tree" />
                  </IconAction>
                  <IconAction label="Open as a room">
                    <Icon name="page" />
                  </IconAction>
                </>
              }
            />
            <span className="lib-t-say">The sales pull is done. 214 claims, three sources.</span>
            {replies.map((r, i) => (
              <span key={i} className="lib-t-say">
                {r}
              </span>
            ))}
            <Composer
              size="small"
              className="lib-thread-reply"
              placeholder="Reply in the thread"
              onSend={(text) => setReplies((l) => [...l.slice(-1), text])}
            />
          </SplitPane.Pane>
        </SplitPane>
      ) : (
        <div className="lib-split lib-split-pane lib-split-closed">{room}</div>
      )}
      <span className="lib-readout">
        <span>room</span>
        <Figure data-specimen="split-value">{threadOpen ? `${Math.round(value * 100)}%` : '100%'}</Figure>
        <span data-specimen="split-log">{log}</span>
        {threadOpen ? null : (
          <Verb
            ref={reopenRef}
            onClick={() => {
              setThreadOpen(true)
              setLog('thread open')
            }}
          >
            open the thread
          </Verb>
        )}
      </span>
    </div>
  )
}

/* ── the write box ────────────────────────────────────────────────────── */

const PERSONAS: ComposerPersonaKind[] = ['all', 'work', 'personal', 'dream']

/* The `+` of a write box: what can ride along, then the model and the
   effort the message is answered with. Called as a function, so the
   write box receives a Composer.Add child it can place inside the box. */
function composerAddMenu({ onFile, onPointer }: { onFile?: () => void; onPointer?: () => void } = {}) {
  return (
    <Composer.Add label="Add to the message">
      <Menu.Item icon={<Icon name="clip" />} onClick={onFile}>
        a file
      </Menu.Item>
      <Menu.Item icon={<Icon name="images" />}>a picture</Menu.Item>
      <Menu.Item icon={<Icon name="reply" />} onClick={onPointer}>
        a pointer to a message
      </Menu.Item>
      <Menu.Separator />
      <Menu.Item icon={<Icon name="tool" />}>model and effort</Menu.Item>
    </Composer.Add>
  )
}

function ComposerDemo() {
  const [persona, setPersona] = React.useState<ComposerPersonaKind>('all')
  const [sent, setSent] = React.useState<Array<{ text: string; boost: boolean }>>([])
  const [pointer, setPointer] = React.useState(true)
  const [chip, setChip] = React.useState(true)
  const [boost, setBoost] = React.useState(false)
  const [heard, setHeard] = React.useState<string[]>([])
  const hear = (what: string) => setHeard((h) => [...h.slice(-2), what])
  return (
    <div className="lib-stack" data-specimen="composer">
      {sent.map((m, i) => (
        <MessageRow key={i} author={<Glyph initial="o" label="Owen" size={24} />} name="Owen" time="just now">
          <MessageRow.Text>{m.text}</MessageRow.Text>
        </MessageRow>
      ))}
      <Composer
        placeholder="Write to the room"
        onSend={(text, details) => {
          setSent((s) => [...s.slice(-1), { text, boost: details.boost }])
          setPointer(false)
          setChip(false)
        }}
        onDictate={() => hear('dictate')}
        onVoice={() => hear('talk')}
        boostWords={['ultrathink', 'think hard']}
        onBoostChange={setBoost}
        crossing={
          <OutsideLine summary="Guests see what you send here">
            <OutsideLine.Group origin="from Acme’s vault">
              <OutsideLine.Guest glyph={<Glyph initial="y" label="Yuki" size={18} guest />}>Yuki</OutsideLine.Guest>
            </OutsideLine.Group>
            <OutsideLine.Group origin="from Owen’s personal vault">
              <OutsideLine.Guest glyph={<Glyph glyph="wing" label="Eiri" size={18} guest />}>Eiri</OutsideLine.Guest>
            </OutsideLine.Group>
          </OutsideLine>
        }
        persona={
          <Menu>
            <Menu.Trigger asChild>
              <Composer.Persona
                persona={persona}
                initial="o"
                note="You write as Owen. Saved in Antevon’s vault."
                aria-label={`persona ${persona}, change who you write as`}
              />
            </Menu.Trigger>
            <Menu.Content side="top" aria-label="personas">
              {PERSONAS.map((p) => (
                <Menu.Item
                  key={p}
                  checked={persona === p}
                  onClick={() => setPersona(p)}
                  icon={<span className="lib-persona-mark" data-persona={p} />}
                >
                  {p}
                </Menu.Item>
              ))}
            </Menu.Content>
          </Menu>
        }
      >
        <Composer.Carry>
          {pointer ? (
            <Composer.Pointer who="Metryon" onRemove={() => setPointer(false)} removeLabel="Drop the pointer">
              Starting on the Q4 view Yuki asked for.
            </Composer.Pointer>
          ) : null}
          {chip ? (
            <Composer.Chip icon="sheet" onRemove={() => setChip(false)} removeLabel="Drop Acme store sales">
              Acme store sales
            </Composer.Chip>
          ) : null}
        </Composer.Carry>
        {composerAddMenu({ onFile: () => setChip(true), onPointer: () => setPointer(true) })}
      </Composer>
      <span className="lib-readout" data-specimen="composer-log">
        boost {boost ? 'on' : 'off'}
        {sent.length ? `, sent “${sent[sent.length - 1].text}”${sent[sent.length - 1].boost ? ' with boost' : ''}` : ''}
        {heard.length ? `, ${heard.join(', ')}` : ''}
      </span>
    </div>
  )
}

/* ── the small write box ─────────────────────────────────────────────── */

function ComposerSmallDemo({ tools, text, specimen }: { tools: ComposerTools; text?: string; specimen: string }) {
  const [log, setLog] = React.useState<string[]>([])
  return (
    <div className="lib-stack lib-composer-small" data-specimen={specimen}>
      <Composer
        size="small"
        tools={tools}
        placeholder="Write about this"
        defaultValue={text}
        onDictate={() => setLog((l) => [...l.slice(-1), 'dictate'])}
        onSend={(sent) => setLog((l) => [...l.slice(-1), `sent “${sent}”`])}
      >
        {composerAddMenu()}
      </Composer>
      <span className="lib-readout" data-specimen={`${specimen}-log`}>
        {log.length ? log.join(', ') : 'Nothing sent yet.'}
      </span>
    </div>
  )
}

/* ── connections ──────────────────────────────────────────────────────── */

function ConnectionVerbs({ leave }: { leave?: boolean }) {
  return (
    <>
      {leave ? null : (
        <IconAction label="Re-scope" caption="change what they can do" size="sm">
          <Icon name="rescope" />
        </IconAction>
      )}
      <IconAction label={leave ? 'Leave' : 'Disconnect'} caption="what synced stays with them" size="sm" tone="consent">
        <Icon name="unlink" />
      </IconAction>
      {leave ? null : (
        <IconAction label="Promote" caption="make them a member" size="sm">
          <Icon name="promote" />
        </IconAction>
      )}
    </>
  )
}

function ConnectionsDemo() {
  const [request, setRequest] = React.useState<'open' | 'allowed' | 'rejected'>('open')
  return (
    <div className="lib-connections" data-specimen="connections">
      <section className="lib-connection-section">
        <h3 className="lib-t-section">Vaults you belong to</h3>
        <ConnectionRow name="Antevon" scope="Owner of the company vault" status="approved" statusLabel="live" verbs={<ConnectionVerbs />} />
        <ConnectionRow name="Hokuei data room" scope="Member, reads and writes order data" status="approved" statusLabel="live" verbs={<ConnectionVerbs />} />
      </section>
      <section className="lib-connection-section">
        <h3 className="lib-t-section">Guest slices you hold</h3>
        <ConnectionRow name="Acme’s vault" scope="Store sales since 2023, reads only" status="approved" statusLabel="live" verbs={<ConnectionVerbs leave />} />
      </section>
      <section className="lib-connection-section">
        <h3 className="lib-t-section">Guests you host</h3>
        {request === 'open' ? (
          <ConnectionRow
            name="Yuki"
            origin="from Acme’s vault"
            scope="Asks to read # acme-forecast"
            status="proposed"
            statusLabel="waits on you"
            tag="boundary"
            onAccept={() => setRequest('allowed')}
            onReject={() => setRequest('rejected')}
            data-specimen="connection-request"
          />
        ) : (
          <ConnectionRow
            name="Yuki"
            origin="from Acme’s vault"
            scope={request === 'allowed' ? 'Reads # acme-forecast' : 'Asked to read # acme-forecast'}
            status={request === 'allowed' ? 'approved' : 'idle'}
            statusLabel={request === 'allowed' ? 'live' : 'rejected'}
            verbs={request === 'allowed' ? <ConnectionVerbs /> : undefined}
          >
            <span className="lib-receipt">
              {request === 'allowed' ? 'Allowed at' : 'Rejected at'} <Figure>14:36</Figure>
              <Verb onClick={() => setRequest('open')}>undo</Verb>
            </span>
          </ConnectionRow>
        )}
        <ConnectionRow
          name="Eiri"
          origin="from Owen’s personal vault"
          scope="Reads and proposes, answers stay provisional"
          status="approved"
          statusLabel="live"
          verbs={<ConnectionVerbs />}
        />
      </section>
    </div>
  )
}

/* ── files ────────────────────────────────────────────────────────────── */

function FilesDemo() {
  return (
    <div className="lib-stack" data-specimen="files">
      <FileGroup title="sales pull" action={<Verb>open the thread</Verb>}>
        <FileRow kind="sheet" kindLabel="sheet" name="Acme store sales" maker="agent" author="Metryon" time="Yesterday at 16:40" />
        <FileRow kind="lens" kindLabel="lens" name="Forecast Q4" maker="agent" author="Metryon" time="14:05" />
      </FileGroup>
      <FileGroup title="Not in a thread">
        <FileRow kind="deck" kindLabel="deck" name="Hokuei pitch" maker="person" author="Owen" time="Mon at 09:12" />
        <FileRow kind="note" kindLabel="note" name="week 44 dips" maker="agent" author="Tory" time="03:10" />
        <FileRow kind="note" kindLabel="note" name="weekly digest" maker="system" author="the vault" time="Fri at 17:00" />
      </FileGroup>
    </div>
  )
}

/* ── the ledger ───────────────────────────────────────────────────────── */

const CLAIMS: Array<[string, string, number, string]> = [
  ['the May filing', 'Hokuei changed its registry address on 2 May', 0.93, 'Mon 21 Sep'],
  ['the March contract', 'Acme must give 90 days’ notice', 0.9, 'Tue 22 Sep'],
  ['the May filing', 'Acme holds 18% of Hokuei’s volume', 0.84, 'Mon 21 Sep'],
  ['the May filing', 'Hokuei runs four resin lines', 0.72, 'Mon 21 Sep'],
  ['the May filing', 'Acme reports capacity of 5.3k units a week', 0.66, 'Mon 21 Sep'],
  ['the March contract', 'Hokuei and Acme stay separate entities', 0.61, 'Tue 22 Sep'],
  ['the March contract', 'Hokuei may re-tender two lines in 2027', 0.42, 'Tue 22 Sep'],
  ['order data', 'Acme may close a further 12 stores in spring', 0.31, 'Wed 23 Sep'],
]

const BRANCHES: Array<{ project: string; branch: string; steps: Step[]; who: React.ReactNode; next: string }> = [
  {
    project: 'hokuei pilot',
    branch: 'Q4 supplier outlook',
    steps: [{ state: 'done' }, { state: 'working', progress: 0.4 }, { state: 'ahead' }],
    who: <Glyph glyph="ruler" label="Metryon" size={18} />,
    next: 'draft the brief',
  },
  {
    project: '',
    branch: 'supplier contradictions',
    steps: [{ state: 'done' }, { state: 'working' }, { state: 'ahead' }],
    who: <Glyph glyph="owl" label="Tory" size={18} />,
    next: 'ask the COO',
  },
  {
    project: 'acme-forecast',
    branch: 'Q4 forecast for Acme',
    steps: [{ state: 'done' }, { state: 'working', progress: 0.65 }, { state: 'ahead' }],
    who: <Glyph glyph="ruler" label="Metryon" size={18} />,
    next: 'fit the forecast',
  },
]

function LedgerDemo() {
  const [opened, setOpened] = React.useState<string | null>(null)
  return (
    <div className="lib-stack" data-specimen="ledger">
      <LedgerTable aria-label="every live branch, by project">
        <LedgerTable.Head>
          <LedgerTable.Cell>Project</LedgerTable.Cell>
          <LedgerTable.Cell>Branch</LedgerTable.Cell>
          <LedgerTable.Cell>Steps</LedgerTable.Cell>
          <LedgerTable.Cell>Who</LedgerTable.Cell>
          <LedgerTable.Cell>Next</LedgerTable.Cell>
        </LedgerTable.Head>
        {BRANCHES.map((b) => (
          <LedgerTable.Row key={b.branch} onClick={() => setOpened(b.branch)}>
            <LedgerTable.Cell className="lib-ledger-project">{b.project}</LedgerTable.Cell>
            <LedgerTable.Cell>{b.branch}</LedgerTable.Cell>
            <LedgerTable.Cell>
              <StepsBar steps={b.steps} />
            </LedgerTable.Cell>
            <LedgerTable.Cell>{b.who}</LedgerTable.Cell>
            <LedgerTable.Cell>{b.next}</LedgerTable.Cell>
          </LedgerTable.Row>
        ))}
      </LedgerTable>
      <span className="lib-readout">{opened ? `Opens the canvas of ${opened}.` : 'Click a row to open its canvas.'}</span>
      <LedgerTable aria-label="claims behind Forecast Q4" data-specimen="claims">
        <LedgerTable.Head>
          <LedgerTable.Cell>Source</LedgerTable.Cell>
          <LedgerTable.Cell>Claim</LedgerTable.Cell>
          <LedgerTable.Cell numeric>Confidence</LedgerTable.Cell>
          <LedgerTable.Cell>Learned</LedgerTable.Cell>
        </LedgerTable.Head>
        {CLAIMS.map(([source, claim, confidence, learned]) => (
          <LedgerTable.Row key={claim}>
            <LedgerTable.Cell>{source}</LedgerTable.Cell>
            <LedgerTable.Cell>
              <ClaimText confidence={confidence}>{claim}</ClaimText>
            </LedgerTable.Cell>
            <LedgerTable.Cell numeric>{confidence.toFixed(2)}</LedgerTable.Cell>
            <LedgerTable.Cell numeric>{learned}</LedgerTable.Cell>
          </LedgerTable.Row>
        ))}
      </LedgerTable>
    </div>
  )
}

/* ── the sections ─────────────────────────────────────────────────────── */

export function PatternSections() {
  return (
    <>
      <Section title="InfoMark">
        <Specimen name="rest on the mark: after 160 ms the note shows to the right of the block when 350 px is free there; press it to open the block beside the room" full>
          <InfoBlock specimen="info-right" open />
        </Specimen>
        <Specimen name="less than 350 px free beside the block: the note shows under the mark" full>
          <div className="lib-info-narrow">
            <InfoBlock specimen="info-under" open />
          </div>
        </Specimen>
      </Section>

      <Section title="NeedsYou">
        <Specimen name="chips: asks grouped by room; a pick or a yes answers at once and the row becomes its record with undo for 5 s; the clock sets an ask aside; rest on the i for its note" full>
          <AsksBlock answers="chips" specimen="needs-you" />
        </Specimen>
        <Specimen name="plain: the same answers as marks and words" full>
          <AsksBlock answers="plain" specimen="needs-you-plain" />
        </Specimen>
      </Section>

      <Section title="MessageRow, HoverBar, DayDivider">
        <Specimen name="the column: three messages and a card; rows start at the left edge, text, card and write box share 620 px; a pin mark ends the name line; go to the pinned message marks it for a moment" full>
          <ColumnDemo />
        </Specimen>
        <Specimen name="attachments, reactions, a provisional answer with its fold, a thread line; hover a row for its actions" full>
          <MessagesDemo />
        </Specimen>
      </Section>

      <Section title="RunFoot">
        <Specimen name="working: interrupt folds it into the receipt" full>
          <RunFootDemo />
        </Specimen>
        <Specimen name="done: the receipt unfolds the calls" full>
          <RunFoot status="done" summary="thought for 54s, 3 tool calls" data-specimen="run-receipt">
            {CALLS.map((c) => (
              <RunFoot.Call key={c.name} name={c.name} by={c.by} duration={c.duration} />
            ))}
          </RunFoot>
        </Specimen>
      </Section>

      <Section title="CrewStack">
        <Specimen name="five, then +1, then the invite; Metryon opens his asks" wide={1}>
          <CrewDemo />
        </Specimen>
        <Specimen name="a member's popover, open" tall={4} full>
          <div className="lib-crew-right">
            <CrewDemo open />
          </div>
        </Specimen>
      </Section>

      <Section title="SplitPane">
        <Specimen name="drag the edge: it leans to 25, 50 and 75; double-click resets; arrow keys move it. The thread pane's head: its title, outline, open as a room, close (Escape in the pane closes it); the small write box is its reply line" full>
          <SplitDemo />
        </Specimen>
      </Section>

      <Section title="Composer, OutsideLine">
        <Specimen name="the portrait in the gutter (its tooltip says who writes and where it is kept), add, a pointer and a chip, the crossing line; empty, the button talks; type and it sends; write ultrathink for the boost line" full>
          <ComposerDemo />
        </Specimen>
        <Specimen name="with text: the button sends" full>
          <Composer
            placeholder="Write to the room"
            defaultValue="Check the supplier notes against the filings."
            onVoice={() => {}}
            onDictate={() => {}}
            persona={<Composer.Persona initial="o" note="You write as Owen. Saved in Antevon’s vault." aria-label="Owen" />}
            data-specimen="composer-text"
          >
            {composerAddMenu()}
          </Composer>
        </Specimen>
        <Specimen name="narrow: the placeholder stays on one line and ends in an ellipsis" wide={1}>
          <div className="lib-composer-narrow" data-specimen="composer-narrow">
            <Composer placeholder="Write to the room, or ask Eiri for the week 44 notes" onVoice={() => {}} />
          </div>
        </Specimen>
        <Specimen name="outside line, open" wide={1}>
          <OutsideLine summary="Guests see what you send here" defaultOpen>
            <OutsideLine.Group origin="from Acme’s vault">
              <OutsideLine.Guest glyph={<Glyph initial="y" label="Yuki" size={18} guest />}>Yuki</OutsideLine.Guest>
            </OutsideLine.Group>
          </OutsideLine>
        </Specimen>
      </Section>

      <Section title="Composer, small">
        <Specimen name="tools on focus (the default): the field alone at rest" wide={1}>
          <ComposerSmallDemo tools="on focus" specimen="composer-small-focus" />
        </Specimen>
        <Specimen name="tools on focus, with text: the tools show at the right" wide={1}>
          <ComposerSmallDemo tools="on focus" text="Keep the promo weeks." specimen="composer-small-focus-text" />
        </Specimen>
        <Specimen name="tools always: add at the left, dictation and send at the right" wide={1}>
          <ComposerSmallDemo tools="always" specimen="composer-small-always" />
        </Specimen>
        <Specimen name="tools always, with text" wide={1}>
          <ComposerSmallDemo tools="always" text="Show week 44 on its own too." specimen="composer-small-always-text" />
        </Specimen>
      </Section>

      <Section title="ConnectionRow">
        <Specimen name="three lists; verbs on hover; a request takes accept and reject" full>
          <ConnectionsDemo />
        </Specimen>
      </Section>

      <Section title="FileGroup, FileRow">
        <Specimen name="grouped by the thread they were born in; the seal says who made each" full>
          <FilesDemo />
        </Specimen>
      </Section>

      <Section title="LedgerTable, ClaimText">
        <Specimen name="branches, then claims printed on the ink ladder by confidence" full>
          <LedgerDemo />
        </Specimen>
      </Section>
    </>
  )
}

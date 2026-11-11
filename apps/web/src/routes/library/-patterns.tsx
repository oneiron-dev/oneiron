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
  type RunSubState,
  type Step,
} from '~/design-system'
import { Section, Specimen } from './-gallery-frame'

/* Pattern sections of the /library gallery: each demo works, on fixture
   data from the app's cast. */

/* ── needs you ────────────────────────────────────────────────────────── */

const SALES_ROWS: Array<[string, string, string]> = [
  ['store 104', '44', '1.38'],
  ['store 117', '44', '1.21'],
  ['store 131', '45', '0.97'],
]

function SalesPicture() {
  return (
    <LedgerTable aria-label="Acme store sales, the stores in question" className="lib-mini-ledger">
      <LedgerTable.Head>
        <LedgerTable.Cell>Store</LedgerTable.Cell>
        <LedgerTable.Cell numeric>Week</LedgerTable.Cell>
        <LedgerTable.Cell numeric>Units, thousands</LedgerTable.Cell>
      </LedgerTable.Head>
      {SALES_ROWS.map(([store, week, units]) => (
        <LedgerTable.Row key={store}>
          <LedgerTable.Cell>{store}</LedgerTable.Cell>
          <LedgerTable.Cell numeric>{week}</LedgerTable.Cell>
          <LedgerTable.Cell numeric>{units}</LedgerTable.Cell>
        </LedgerTable.Row>
      ))}
    </LedgerTable>
  )
}

interface AskFixture {
  id: string
  asker: React.ReactNode
  question: string
  urgency?: { reason: string; deadline?: string }
  body: React.ReactNode
}

const ASKS: AskFixture[] = [
  {
    id: 'promo',
    asker: <Glyph glyph="ruler" label="Metryon" size={18} />,
    question: 'Should the fit treat weeks 44 to 46 as promo weeks?',
    urgency: { reason: 'blocks the fit' },
    body: (
      <NeedsYou.Picks>
        <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
        <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
        <NeedsYou.Pick value="week-44">only week 44</NeedsYou.Pick>
        <NeedsYou.OwnAnswer />
        <NeedsYou.Later />
      </NeedsYou.Picks>
    ),
  },
  {
    id: 'stores',
    asker: <Glyph initial="y" label="Yuki" size={18} guest />,
    question: 'Edit Acme store sales: drop the 12 stores that close in November',
    urgency: { reason: 'due Friday', deadline: '17:00' },
    body: (
      <>
        <NeedsYou.Context>
          <SalesPicture />
        </NeedsYou.Context>
        <NeedsYou.Picks>
          <NeedsYou.Pick value="accept" word="accepted">
            accept
          </NeedsYou.Pick>
          <NeedsYou.Pick value="decline" word="declined" tone="consent">
            decline
          </NeedsYou.Pick>
          <NeedsYou.OwnAnswer />
          <NeedsYou.Later />
        </NeedsYou.Picks>
      </>
    ),
  },
  {
    id: 'extracts',
    asker: <Glyph glyph="owl" label="Tory" size={18} />,
    question: 'Pull paid registry extracts at ¥800 each?',
    body: (
      <>
        <NeedsYou.Command>Pull the paid extracts for the three Hokuei suppliers, ¥800 each.</NeedsYou.Command>
        <NeedsYou.Picks>
          <NeedsYou.Pick value="allow" word="allowed once">
            allow once
          </NeedsYou.Pick>
          <NeedsYou.Pick value="deny" word="denied" tone="consent">
            deny
          </NeedsYou.Pick>
          <NeedsYou.OwnAnswer />
          <NeedsYou.Later />
        </NeedsYou.Picks>
      </>
    ),
  },
  {
    id: 'join',
    asker: <Glyph glyph="wing" label="Eiri" size={18} />,
    question: 'Join # hokuei pilot for up to a tenth of her week',
    body: (
      <>
        <NeedsYou.Plan>
          <NeedsYou.Step>read the Hokuei email map</NeedsYou.Step>
          <NeedsYou.Step>draft two openers for the COO</NeedsYou.Step>
          <NeedsYou.Step>send the one you pick through Yuki</NeedsYou.Step>
          <NeedsYou.Step>log each send in the thread</NeedsYou.Step>
          <NeedsYou.Step>stop at a tenth of the week</NeedsYou.Step>
        </NeedsYou.Plan>
        <NeedsYou.Picks>
          <NeedsYou.Pick value="allow" word="let in">
            let in
          </NeedsYou.Pick>
          <NeedsYou.Pick value="deny" word="not let in" tone="consent">
            no
          </NeedsYou.Pick>
          <NeedsYou.Later />
        </NeedsYou.Picks>
      </>
    ),
  },
  {
    id: 'dip',
    asker: <Glyph glyph="laurel" label="Antevon" size={18} />,
    question: 'Acme’s week 44 dip comes back every year',
    body: (
      <NeedsYou.Picks>
        <NeedsYou.Pick value="accept" word="accepted">
          accept
        </NeedsYou.Pick>
        <NeedsYou.Pick value="reject" word="rejected" tone="consent">
          reject
        </NeedsYou.Pick>
        <NeedsYou.OwnAnswer placeholder="What is true instead" />
        <NeedsYou.Later />
      </NeedsYou.Picks>
    ),
  },
]

function NeedsYouDemo() {
  const [gone, setGone] = React.useState<string[]>([])
  const [log, setLog] = React.useState('Nothing settled yet.')
  const [round, setRound] = React.useState(0)
  const asks = ASKS.filter((a) => !gone.includes(a.id))
  return (
    <div className="lib-stack">
      {asks.length ? (
        <NeedsYou
          key={round}
          aria-label="needs you in # acme-forecast"
          data-specimen="needs-you"
          onSettle={(id, value) => {
            setGone((g) => [...g, id])
            setLog(`${id}: ${value}`)
          }}
          onLater={(id) => {
            setGone((g) => [...g, id])
            setLog(`${id}: later`)
          }}
        >
          {asks.map((a) => (
            <NeedsYou.Item key={a.id} id={a.id} asker={a.asker} question={a.question} urgency={a.urgency}>
              {a.body}
            </NeedsYou.Item>
          ))}
        </NeedsYou>
      ) : null}
      <span className="lib-readout">
        <span>{log}</span>
        <Verb
          onClick={() => {
            setGone([])
            setRound((r) => r + 1)
            setLog('Nothing settled yet.')
          }}
        >
          bring them back
        </Verb>
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
        author={<Glyph glyph="ruler" label="Metryon" size={32} />}
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
      <MessageRow author={<Glyph initial="o" label="Owen" size={32} />} name="Owen" time="46 min ago" data-specimen="message-reactions">
        <MessageRow.Text>Eiri, do my notes say anything about Acme’s promo calendar?</MessageRow.Text>
        <MessageRow.Reactions onAdd={() => toggle('👀')}>
          {reactions.map((r) => (
            <MessageRow.Reaction key={r.emoji} emoji={r.emoji} count={r.count} pressed={r.mine} who={r.who} onClick={() => toggle(r.emoji)} />
          ))}
        </MessageRow.Reactions>
        <MessageActions saved={saved.includes('m2')} onSave={save('m2')} />
      </MessageRow>
      <MessageRow author={<Glyph glyph="wing" label="Eiri" size={32} guest />} name="Eiri" time="44 min ago" provisional>
        <MessageRow.Fold summary="from Owen’s vault">
          <span>Answered from Owen’s personal vault.</span>
          <span>Nothing was copied into this vault.</span>
          <span>It stays provisional until a member accepts it.</span>
        </MessageRow.Fold>
        <MessageRow.Text>Your notes from the August call say the promo runs in weeks 44 to 46.</MessageRow.Text>
        <MessageActions saved={saved.includes('m3')} onSave={save('m3')} />
      </MessageRow>
      <MessageRow author={<Glyph glyph="ruler" label="Metryon" size={32} />} name="Metryon" time="31 min ago" data-specimen="message-thread">
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
              <NeedsYou.Item
                id="pop-promo"
                asker={<Glyph glyph="ruler" label="Metryon" size={18} />}
                question="Should the fit treat weeks 44 to 46 as promo weeks?"
                urgency={{ reason: 'blocks the fit' }}
              >
                <NeedsYou.Picks>
                  <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
                  <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
                  <NeedsYou.OwnAnswer />
                  <NeedsYou.Later />
                </NeedsYou.Picks>
              </NeedsYou.Item>
              <NeedsYou.Item id="pop-band" asker={<Glyph glyph="ruler" label="Metryon" size={18} />} question="How should I split the Q4 band?">
                <NeedsYou.Picks>
                  <NeedsYou.Pick value="supplier">by supplier</NeedsYou.Pick>
                  <NeedsYou.Pick value="region">by region</NeedsYou.Pick>
                  <NeedsYou.Later />
                </NeedsYou.Picks>
              </NeedsYou.Item>
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
          <CrewStack.ListRow glyph={<Glyph initial="o" label="Owen" />} href="#Owen">
            Owen (you)
          </CrewStack.ListRow>
          <CrewStack.ListRow glyph={<Glyph initial="y" label="Yuki" guest />} href="#Yuki">
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
  return (
    <div className="lib-stack lib-split-wrap">
      <SplitPane
        className="lib-split"
        defaultValue={0.5}
        onValueChange={setValue}
        min={0.25}
        max={0.8}
        storageKey="sl-library-split"
        data-specimen="split"
      >
        <SplitPane.Pane className="lib-split-pane">
          <span className="lib-t-section">acme-forecast</span>
          <span className="lib-t-say">Starting on the Q4 view Yuki asked for.</span>
        </SplitPane.Pane>
        <SplitPane.Handle aria-label="resize the thread pane" />
        <SplitPane.Pane className="lib-split-pane">
          <span className="lib-t-section">Q4 forecast for Acme</span>
          <span className="lib-t-say">The sales pull is done. 214 claims, three sources.</span>
        </SplitPane.Pane>
      </SplitPane>
      <span className="lib-readout">
        <span>room</span>
        <Figure data-specimen="split-value">{Math.round(value * 100)}%</Figure>
      </span>
    </div>
  )
}

/* ── the write box ────────────────────────────────────────────────────── */

const PERSONAS: ComposerPersonaKind[] = ['all', 'work', 'personal', 'dream']

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
        <MessageRow key={i} author={<Glyph initial="o" label="Owen" size={32} />} name="Owen" time="just now">
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
        savedIn="Saved in: your vault"
        boostWords={['ultrathink', 'think hard']}
        onBoostChange={setBoost}
        persona={
          <Menu>
            <Menu.Trigger asChild>
              <Composer.Persona persona={persona} initial="o" aria-label={`persona ${persona}, change who you write as`} />
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
        <OutsideLine summary="Guests see what you send here">
          <OutsideLine.Group origin="from Acme’s vault">
            <OutsideLine.Guest glyph={<Glyph initial="y" label="Yuki" size={18} guest />}>Yuki</OutsideLine.Guest>
          </OutsideLine.Group>
          <OutsideLine.Group origin="from Owen’s personal vault">
            <OutsideLine.Guest glyph={<Glyph glyph="wing" label="Eiri" size={18} guest />}>Eiri</OutsideLine.Guest>
          </OutsideLine.Group>
        </OutsideLine>
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
        <Composer.Add label="Add to the message">
          <Menu.Item icon={<Icon name="clip" />} onClick={() => setChip(true)}>
            a file
          </Menu.Item>
          <Menu.Item icon={<Icon name="images" />}>a picture</Menu.Item>
          <Menu.Item icon={<Icon name="reply" />} onClick={() => setPointer(true)}>
            a pointer to a message
          </Menu.Item>
        </Composer.Add>
      </Composer>
      <span className="lib-readout" data-specimen="composer-log">
        boost {boost ? 'on' : 'off'}
        {sent.length ? `, sent “${sent[sent.length - 1].text}”${sent[sent.length - 1].boost ? ' with boost' : ''}` : ''}
        {heard.length ? `, ${heard.join(', ')}` : ''}
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
      <Section title="NeedsYou">
        <Specimen name="in a room: the first open, picks apply with undo, the next opens" full>
          <NeedsYouDemo />
        </Specimen>
      </Section>

      <Section title="MessageRow, HoverBar, DayDivider">
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
        <Specimen name="drag the edge: it leans to 25, 50 and 75; double-click resets; arrow keys move it" full>
          <SplitDemo />
        </Specimen>
      </Section>

      <Section title="Composer, OutsideLine">
        <Specimen name="persona, add, a pointer and a chip, the outside line; empty, the button talks; type and it sends; write ultrathink for the boost line" full>
          <ComposerDemo />
        </Specimen>
        <Specimen name="outside line, open" wide={1}>
          <OutsideLine summary="Guests see what you send here" defaultOpen>
            <OutsideLine.Group origin="from Acme’s vault">
              <OutsideLine.Guest glyph={<Glyph initial="y" label="Yuki" size={18} guest />}>Yuki</OutsideLine.Guest>
            </OutsideLine.Group>
          </OutsideLine>
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

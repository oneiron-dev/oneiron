import * as React from 'react'
import { applyTheme, readTheme, type Theme } from '~/components/safelight/hooks'
import {
  ACTIVITY_KIND_LABEL,
  ActivityDay,
  ActivityList,
  ActivityMark,
  ActivityRow,
  AppFrame,
  Composer,
  CrewStack,
  DayDivider,
  Glyph,
  Icon,
  IconAction,
  Island,
  Menu,
  MessageRow,
  MicroSidebar,
  NeedsYou,
  PeopleTable,
  PlaceHead,
  SafelightRoot,
  Sidebar,
  RolePicker,
  RoleWord,
  SortCycle,
  StatusDot,
  VaultSwitch,
  Verb,
  WindowGround,
  Figure,
  type ActivityAge,
  type ActivityKind,
  type IconName,
  type RoleAct,
  type RoleOption,
  type SortCycleOption,
  type Theme as LibraryTheme,
  type VaultSwitchVault,
} from '~/design-system'
import { Section, Specimen } from './-gallery-frame'
import { ANTEVON, EIRI, METRYON, TORY, type Resident } from './-identity'
import { GALLERY_THEMES } from './-themes'

/* Frame sections of the /library gallery: the sidebar, the microsidebar,
   the app frame on each theme, the vault switch, the activity list, the
   sort cycle, the people table and its roles. Every demo works on fixture
   data from the app's cast. */

const line = (r: Resident, size: 18 | 24 = 18) => (
  <Glyph glyph={r.glyph} label={r.name} form="line" ink={r.ink} size={size} />
)

/* ── vaults and the account parts of the switch ───────────────────────── */

const VAULTS: VaultSwitchVault[] = [
  { id: 'antevon', name: 'antevon', caption: 'the house' },
  { id: 'owen', name: 'owen', caption: 'yours', needsYou: 2 },
  { id: 'acme', name: 'acme', caption: 'a guest slice', needsYou: 1 },
]

function ThemeItems() {
  const [theme, setTheme] = React.useState<Theme | null>(null)
  React.useEffect(() => setTheme(readTheme()), [])
  return (
    <>
      {(['light', 'system', 'dark'] as const).map((t) => (
        <Menu.Item
          key={t}
          checked={theme === t}
          closeOnSelect={false}
          onClick={() => {
            applyTheme(t)
            setTheme(t)
          }}
        >
          {t}
        </Menu.Item>
      ))}
    </>
  )
}

function AccountParts() {
  const [persona, setPersona] = React.useState('all')
  return (
    <>
      <Menu.Heading>Personas</Menu.Heading>
      {['all', 'work', 'personal'].map((p) => (
        <Menu.Item
          key={p}
          checked={persona === p}
          closeOnSelect={false}
          onClick={() => setPersona(p)}
          icon={<Glyph initial="o" label={`Owen, ${p}`} size={18} />}
        >
          {p}
        </Menu.Item>
      ))}
      <Menu.Heading>Devices</Menu.Heading>
      <Menu.Line icon={<Icon name="device" />}>
        this laptop
        <StatusDot state="approved" label="in use" />
      </Menu.Line>
      <Menu.Line icon={<Icon name="phone" />}>
        phone
        <Figure>09:12</Figure>
      </Menu.Line>
      <Menu.Heading>Appearance</Menu.Heading>
      <ThemeItems />
      <Menu.Separator />
      <Menu.Item icon={<Icon name="signOut" />}>sign out</Menu.Item>
    </>
  )
}

function VaultSwitchDemo({ defaultOpen = false, specimen }: { defaultOpen?: boolean; specimen?: string }) {
  const [current, setCurrent] = React.useState('antevon')
  const [made, setMade] = React.useState(0)
  return (
    <div className="lib-stack">
      <VaultSwitch
        vaults={VAULTS}
        currentId={current}
        onSwitch={setCurrent}
        onCreate={() => setMade((n) => n + 1)}
        defaultOpen={defaultOpen}
        data-specimen={specimen}
      >
        <AccountParts />
      </VaultSwitch>
      <span className="lib-readout" data-specimen={specimen ? `${specimen}-value` : undefined}>
        in {current}
        {made ? <Figure>{made}</Figure> : null}
      </span>
    </div>
  )
}

/* ── activity ──────────────────────────────────────────────────────────── */

interface ActivityFixture {
  id: string
  kind: ActivityKind
  who: Resident | { name: string; initial: string; guest?: boolean }
  where: string
  sentence: string
  when: string
  age: ActivityAge
  /* Minutes before now: the newest-first order. */
  ago: number
}

const ACTIVITY: ActivityFixture[] = [
  { id: 'promo', kind: 'needs-you', who: METRYON, where: 'acme-forecast', sentence: 'Should the fit treat weeks 44 to 46 as promo weeks?', when: '14:02', age: 'today', ago: 8 },
  { id: 'filings', kind: 'running', who: TORY, where: 'hokuei pilot', sentence: 'Checking the May filings for the three suppliers', when: '13:40', age: 'today', ago: 30 },
  { id: 'extracts', kind: 'needs-you', who: TORY, where: 'the house', sentence: 'Pull paid registry extracts at ¥800 each?', when: '13:12', age: 'today', ago: 58 },
  { id: 'stores', kind: 'mention', who: { name: 'Yuki', initial: 'y' }, where: 'acme-forecast', sentence: '@Owen can you confirm the store list before Friday?', when: '12:18', age: 'today', ago: 112 },
  { id: 'edit', kind: 'outside', who: { name: 'Yuki', initial: 'y', guest: true }, where: 'acme-forecast', sentence: 'Proposed an edit to Acme store sales', when: '11:05', age: 'today', ago: 185 },
  { id: 'nightly', kind: 'done', who: ANTEVON, where: 'the house', sentence: 'Nightly consolidation finished: 42 claims went in', when: '23:10', age: 'yesterday', ago: 900 },
  { id: 'passport', kind: 'reaction', who: EIRI, where: 'Personal', sentence: 'Reacted to your note on the passport photos', when: '18:22', age: 'yesterday', ago: 1188 },
  { id: 'outlook', kind: 'done', who: METRYON, where: 'hokuei pilot', sentence: 'The Q4 supplier outlook is drafted', when: '9 Nov', age: 'older', ago: 3000 },
]

const SORTS: SortCycleOption[] = [
  { value: 'newest', label: 'newest first' },
  { value: 'urgency', label: 'most urgent first' },
  { value: 'room', label: 'by room' },
]

const URGENCY: Record<ActivityKind, number> = { 'needs-you': 0, outside: 1, mention: 2, running: 3, reaction: 4, done: 5 }

function sortActivity(rows: ActivityFixture[], by: string): ActivityFixture[] {
  const out = rows.slice()
  if (by === 'urgency') out.sort((a, b) => URGENCY[a.kind] - URGENCY[b.kind] || a.ago - b.ago)
  else if (by === 'room') out.sort((a, b) => a.where.localeCompare(b.where) || a.ago - b.ago)
  else out.sort((a, b) => a.ago - b.ago)
  return out
}

const DAY_WORD: Record<ActivityAge, string> = { today: 'Today', yesterday: 'Yesterday', older: 'Earlier' }

function whoGlyph(who: ActivityFixture['who']) {
  return 'glyph' in who ? line(who) : <Glyph initial={who.initial} label={who.name} size={18} guest={who.guest} />
}

/* The activity list with its sort; the first needs-you row is open and its
   picks apply with undo; a settled row folds away and the next opens. */
function ActivityDemo({ specimen, head = true }: { specimen: string; head?: boolean }) {
  const [sort, setSort] = React.useState('newest')
  /* The row whose item is open elsewhere: a click on a row moves it. */
  const [selected, setSelected] = React.useState('filings')
  const [gone, setGone] = React.useState<string[]>([])
  const [log, setLog] = React.useState<string[]>([])
  const live = sortActivity(
    ACTIVITY.filter((a) => !gone.includes(a.id)),
    sort,
  )
  const openId = live.find((a) => a.kind === 'needs-you')?.id
  const byDay = sort === 'newest'
  const settle = (id: string, word: string) => {
    setGone((g) => [...g, id])
    setLog((l) => [...l, `${id} ${word}`])
  }
  const rows: React.ReactNode[] = []
  let day: ActivityAge | null = null
  for (const a of live) {
    if (byDay && a.age !== day) {
      day = a.age
      rows.push(<ActivityDay key={`day-${day}`}>{DAY_WORD[day]}</ActivityDay>)
    }
    rows.push(
      <ActivityRow
        key={a.id}
        id={a.id}
        kind={a.kind}
        glyph={whoGlyph(a.who)}
        name={a.who.name}
        where={a.where}
        sentence={a.sentence}
        when={a.when}
        age={a.age}
        open={a.id === openId}
        selected={a.id === selected}
        onOpen={() => setSelected(a.id)}
        onSettle={(id, value) => settle(id, value)}
        onLater={(id) => settle(id, 'later')}
      >
        {a.kind === 'needs-you' ? (
          <NeedsYou.Picks>
            {a.id === 'promo' ? (
              <>
                <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
                <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
                <NeedsYou.Pick value="week-44">only week 44</NeedsYou.Pick>
              </>
            ) : (
              <>
                <NeedsYou.Pick value="allow" word="allowed once">
                  allow once
                </NeedsYou.Pick>
                <NeedsYou.Pick value="decline" word="declined" tone="consent">
                  decline
                </NeedsYou.Pick>
              </>
            )}
            <NeedsYou.OwnAnswer />
            <NeedsYou.Later />
          </NeedsYou.Picks>
        ) : undefined}
      </ActivityRow>,
    )
  }
  return (
    <div className="lib-activity" data-specimen={specimen}>
      {head ? (
        <div className="lib-activity-head">
          <h2 className="lib-activity-title">
            <Icon name="activity" size={18} />
            Activity
          </h2>
          <SortCycle options={SORTS} value={sort} onValueChange={setSort} data-specimen={`${specimen}-sort`} />
        </div>
      ) : null}
      <ActivityList>{rows}</ActivityList>
      <span className="lib-readout" data-specimen={`${specimen}-log`}>
        {`${selected} is open in the work area. `}
        {log.length ? log.join(', ') : 'Nothing settled yet.'}
        {gone.length ? (
          <button
            type="button"
            className="lib-pick"
            onClick={() => {
              setGone([])
              setLog([])
            }}
          >
            bring them back
          </button>
        ) : null}
      </span>
    </div>
  )
}

/* The activity list in compact form, for a sidebar: two lines a row, the
   selected row lit; a needs-you row opens in the work area instead of
   unfolding its picks. */
function ActivityCompactDemo({ specimen, readout = true }: { specimen: string; readout?: boolean }) {
  const [selected, setSelected] = React.useState('promo')
  const rows: React.ReactNode[] = []
  let day: ActivityAge | null = null
  for (const a of sortActivity(ACTIVITY, 'newest')) {
    if (a.age !== day) {
      day = a.age
      rows.push(<ActivityDay key={`day-${day}`}>{DAY_WORD[day]}</ActivityDay>)
    }
    rows.push(
      <ActivityRow
        key={a.id}
        id={a.id}
        kind={a.kind}
        glyph={whoGlyph(a.who)}
        name={a.who.name}
        where={a.where}
        sentence={a.sentence}
        when={a.when}
        age={a.age}
        open={a.kind === 'needs-you'}
        selected={a.id === selected}
        onOpen={() => setSelected(a.id)}
      />,
    )
  }
  return (
    <div className="lib-activity-compact" data-specimen={specimen}>
      <ActivityList density="compact" aria-label="activity">
        {rows}
      </ActivityList>
      {readout ? (
        <span className="lib-readout" data-specimen={`${specimen}-open`}>
          {selected} is open in the work area
        </span>
      ) : null}
    </div>
  )
}

/* ── the head of the work area ─────────────────────────────────────────── */

/* A place head with the crew and two actions at the right. */
function PlaceHeadDemo({ specimen, origin = false, title }: { specimen: string; origin?: boolean; title?: string }) {
  const [back, setBack] = React.useState(0)
  return (
    <PlaceHead
      level={2}
      icon={origin ? <Icon name="thread" /> : <Icon name="hash" />}
      title={title ?? (origin ? 'fit the Q4 forecast' : 'acme-forecast')}
      origin={
        origin ? (
          <>
            a task of
            <Verb onClick={() => setBack((n) => n + 1)}>the Q4 view</Verb>
            {back ? <Figure>{back}</Figure> : null}
          </>
        ) : undefined
      }
      data-specimen={specimen}
    >
      <CrewStack aria-label="crew" max={3}>
        <CrewStack.Member name="Owen, you">
          <Glyph initial="o" label="Owen" />
        </CrewStack.Member>
        <CrewStack.Member name="Metryon">
          <Glyph glyph="ruler" label="Metryon" />
        </CrewStack.Member>
        <CrewStack.Member name="Tory">
          <Glyph glyph="owl" label="Tory" />
        </CrewStack.Member>
        <CrewStack.Member name="Yuki, a guest">
          <Glyph initial="y" label="Yuki" guest />
        </CrewStack.Member>
      </CrewStack>
      <IconAction label="Outline">
        <Icon name="tree" />
      </IconAction>
      <IconAction label="More">
        <Icon name="more" />
      </IconAction>
    </PlaceHead>
  )
}

/* ── people and roles ─────────────────────────────────────────────────── */

const ROLES: RoleOption[] = [
  { id: 'owner', name: 'owner', job: 'Holds the vault: sets its rules, pays for it, can delete it.' },
  { id: 'deputy', name: 'deputy', job: 'Acts for the owner; asks first before acts that cannot be undone.', hint: 'usually an agent' },
  { id: 'admin', name: 'admin', job: 'Adds and removes people and gives them roles.' },
  { id: 'steward', name: 'steward', job: 'Reads and organises the memory; suggests who joins.', hint: 'usually an agent' },
  { id: 'member', name: 'member', job: 'Works inside the vault as its scopes allow.' },
  { id: 'delegate', name: 'delegate', job: 'Works under a narrow grant that ends on a date.' },
  { id: 'guest', name: 'guest', job: 'Reads a scoped copy and proposes back.' },
]

const ACTS: RoleAct[] = [
  { name: 'erase', mode: 'always-ask' },
  { name: 'delete the vault', mode: 'always-ask' },
  { name: 'transfer ownership', mode: 'always-ask' },
  { name: 'add a member', mode: 'ask-when-unsure' },
  { name: 'give a role', mode: 'ask-when-unsure' },
  { name: 'connect a vault', mode: 'just-go' },
]

const roleOf = (id: string) => ROLES.find((r) => r.id === id) ?? ROLES[4]

/* A role word that opens the picker: the word follows the pick. */
function ChangeableRole({ initial, who }: { initial: string; who: string }) {
  const [role, setRole] = React.useState(initial)
  const [acts, setActs] = React.useState(ACTS)
  return (
    <RoleWord name={roleOf(role).name} canChange data-specimen={`role-${who}`}>
      <RolePicker roles={ROLES} value={role} onValueChange={setRole} acts={acts} onActsChange={setActs} />
    </RoleWord>
  )
}

function ReadOnlyRole({ id, who }: { id: string; who: string }) {
  const r = roleOf(id)
  return <RoleWord name={r.name} job={r.job} data-specimen={`role-${who}`} />
}

function PeopleDemo() {
  return (
    <PeopleTable aria-label="people of the antevon vault" className="lib-people" data-specimen="people">
      <PeopleTable.Head>
        <PeopleTable.Cell>Who</PeopleTable.Cell>
        <PeopleTable.Cell>Role</PeopleTable.Cell>
      </PeopleTable.Head>
      <PeopleTable.Row glyph={<Glyph initial="o" label="Owen" size={18} />} name="Owen" roleWord={<ReadOnlyRole id="owner" who="owen" />}>
        <PeopleTable.Row glyph={line(ANTEVON)} name="Antevon" roleWord={<ChangeableRole initial="steward" who="antevon" />}>
          <PeopleTable.Row glyph={line(METRYON)} name="Metryon" roleWord={<ChangeableRole initial="member" who="metryon" />} />
          <PeopleTable.Row glyph={line(TORY)} name="Tory" roleWord={<ChangeableRole initial="delegate" who="tory" />} />
        </PeopleTable.Row>
        <PeopleTable.Row glyph={line(EIRI)} name="Eiri" roleWord={<ChangeableRole initial="deputy" who="eiri" />} />
      </PeopleTable.Row>
      <PeopleTable.Row
        glyph={<Glyph initial="y" label="Yuki" size={18} guest />}
        name="Yuki"
        origin="from Acme’s vault"
        roleWord={<ReadOnlyRole id="guest" who="yuki" />}
      />
    </PeopleTable>
  )
}

/* ── the sidebar ──────────────────────────────────────────────────────── */

interface RoomFixture {
  id: string
  label: string
  shared?: boolean
  icon: 'hash' | 'thread'
}

const ROOMS: RoomFixture[] = [
  { id: 'acme-forecast', label: 'acme-forecast', shared: true, icon: 'hash' },
  { id: 'q4', label: 'Q4 forecast for Acme', icon: 'thread' },
  { id: 'fun', label: 'fun', icon: 'hash' },
  { id: 'the-house', label: 'the house', icon: 'hash' },
  { id: 'supplier-talks', label: 'supplier talks', icon: 'hash' },
]

const GROUPS = ['top', 'pinned', 'rooms', 'projects', 'vault']

/* The rooms of the hokuei pilot: more than five, so the rest fold. */
const HOKUEI_ROOMS = [
  { id: 'outlook', label: 'supplier outlook' },
  { id: 'filings', label: 'filings' },
  { id: 'extracts', label: 'registry extracts' },
  { id: 'outreach', label: 'coo outreach' },
  { id: 'pricing', label: 'pricing' },
  { id: 'logistics', label: 'logistics' },
  { id: 'weekly', label: 'weekly sync' },
]

/* A whole sidebar on fixture data, every row state in it: the head (the
   vault switch, or the caller's), the top rows with a caption and a count,
   pinned, rooms, projects with their rooms one level under them, and the
   vault. Rows and groups reorder; pinning moves a room between rooms and
   pinned. A thread shows only while it is pinned. */
function SidebarDemo({
  specimen,
  head,
  childIndent,
  collapsed: collapsedProp,
  onCollapsedChange,
}: {
  specimen: string
  head?: React.ReactNode
  childIndent?: 'icon' | 'none'
  collapsed?: boolean
  onCollapsedChange?: (collapsed: boolean) => void
}) {
  const [groups, setGroups] = React.useState(GROUPS)
  const [pinned, setPinned] = React.useState(['acme-forecast', 'q4'])
  const [rooms, setRooms] = React.useState(['fun', 'the-house', 'supplier-talks'])
  const [current, setCurrent] = React.useState('activity')
  const [vault, setVault] = React.useState('antevon')
  const [collapsedOwn, setCollapsedOwn] = React.useState(false)
  const collapsed = collapsedProp ?? collapsedOwn
  const setCollapsed = onCollapsedChange ?? setCollapsedOwn
  const room = (id: string) => ROOMS.find((r) => r.id === id)!
  const pin = (id: string, on: boolean) => {
    if (on) {
      setRooms((l) => l.filter((x) => x !== id))
      setPinned((l) => [...l, id])
    } else {
      setPinned((l) => l.filter((x) => x !== id))
      if (room(id).icon !== 'thread') setRooms((l) => [id, ...l])
    }
  }
  const roomLeaf = (id: string, label: string) => (
    <Sidebar.Row key={id} id={id} icon={<Icon name="hash" />} label={label} current={current === id} onClick={() => setCurrent(id)} />
  )
  const roomRow = (id: string, isPinned: boolean) => {
    const r = room(id)
    return (
      <Sidebar.Row
        key={id}
        id={id}
        icon={<Icon name={r.icon} />}
        label={r.label}
        shared={r.shared}
        current={current === id}
        onClick={() => setCurrent(id)}
        pinned={isPinned}
        onPinChange={(on) => pin(id, on)}
      />
    )
  }
  const part: Record<string, React.ReactNode> = {
    top: (
      <Sidebar.Group key="top" id="top">
        <Sidebar.Row id="eiri" glyph={line(EIRI)} label="eiri" caption="yours" current={current === 'eiri'} onClick={() => setCurrent('eiri')} />
        <Sidebar.Row
          id="antevon"
          glyph={line(ANTEVON)}
          label="Antevon"
          caption="speaks for antevon"
          current={current === 'antevon'}
          onClick={() => setCurrent('antevon')}
        />
        <Sidebar.Row
          id="activity"
          icon={<Icon name="activity" />}
          label="activity"
          count={3}
          current={current === 'activity'}
          onClick={() => setCurrent('activity')}
        />
      </Sidebar.Group>
    ),
    pinned: (
      <Sidebar.Group key="pinned" id="pinned" label="pinned" reorderable onReorder={setPinned}>
        {pinned.map((id) => roomRow(id, true))}
      </Sidebar.Group>
    ),
    rooms: (
      <Sidebar.Group key="rooms" id="rooms" label="rooms" reorderable onReorder={setRooms}>
        {rooms.map((id) => roomRow(id, false))}
      </Sidebar.Group>
    ),
    projects: (
      <Sidebar.Group key="projects" id="projects" label="projects">
        <Sidebar.Row
          id="hokuei"
          icon={<Icon name="project" />}
          label="hokuei pilot"
          current={current === 'hokuei'}
          onClick={() => setCurrent('hokuei')}
          childRows={HOKUEI_ROOMS.map((r) => roomLeaf(r.id, r.label))}
        />
        <Sidebar.Row
          id="personal"
          icon={<Icon name="project" />}
          label="Personal"
          current={current === 'personal'}
          onClick={() => setCurrent('personal')}
          childRows={roomLeaf('passport', 'passport')}
        />
      </Sidebar.Group>
    ),
    vault: (
      <Sidebar.Group key="vault" id="vault">
        <Sidebar.Row id="vault" icon={<Icon name="vault" />} label="vault" current={current === 'vault'} onClick={() => setCurrent('vault')} />
      </Sidebar.Group>
    ),
  }
  return (
    <div className="lib-sidebar-demo" data-specimen={specimen}>
      <div className="lib-sheet-stage">
        <Sidebar collapsed={collapsed} childIndent={childIndent} onGroupReorder={setGroups} aria-label="places">
          {head ?? (
            <Sidebar.Head>
              <VaultSwitch vaults={VAULTS} currentId={vault} onSwitch={setVault} onCreate={() => {}}>
                <AccountParts />
              </VaultSwitch>
              <IconAction label="Search" caption="press ⌘K">
                <Icon name="search" />
              </IconAction>
              <IconAction label={collapsed ? 'Expand the sidebar' : 'Collapse to icons'} onClick={() => setCollapsed(!collapsed)}>
                <Icon name="sidebar" />
              </IconAction>
            </Sidebar.Head>
          )}
          {groups.map((g) => part[g])}
        </Sidebar>
      </div>
      <p className="lib-field-readout" data-specimen={`${specimen}-order`}>
        {groups.join(' ')} | {pinned.join(' ')} | {rooms.join(' ')}
        {pinned.includes('q4') ? null : (
          <button type="button" className="lib-pick lib-field-pick" onClick={() => setPinned((l) => [...l, 'q4'])}>
            pin the thread back
          </button>
        )}
      </p>
    </div>
  )
}

/* ── Home's sidebar in the frame ──────────────────────────────────────── */

/* The first line of Home's sidebar (inside Sidebar.Head): the vault's
   name opens the vault switch; search and the fold action at the right. */
function HomeHeadParts() {
  const [vault, setVault] = React.useState('antevon')
  return (
    <>
      <VaultSwitch vaults={VAULTS} currentId={vault} onSwitch={setVault} onCreate={() => {}}>
        <AccountParts />
      </VaultSwitch>
      <IconAction label="Search" caption="press ⌘K">
        <Icon name="search" />
      </IconAction>
      <AppFrame.Fold />
    </>
  )
}

/* Home's sidebar: the person's companion and the vault's lead, then
   pinned, rooms and projects. The person is Owen. */
function HomeSidebar({ specimen }: { specimen: string }) {
  const [current, setCurrent] = React.useState('eiri')
  const row = (id: string, label: string, icon: IconName, extra: { shared?: boolean; childRows?: React.ReactNode } = {}) => (
    <Sidebar.Row key={id} id={id} icon={<Icon name={icon} />} label={label} current={current === id} onClick={() => setCurrent(id)} {...extra} />
  )
  return (
    <Sidebar aria-label="Home" data-specimen={specimen}>
      <Sidebar.Head>
        <HomeHeadParts />
      </Sidebar.Head>
      <Sidebar.Group id="top">
        <Sidebar.Row id="eiri" glyph={line(EIRI)} label="eiri" current={current === 'eiri'} onClick={() => setCurrent('eiri')} />
        <Sidebar.Row id="antevon" glyph={line(ANTEVON)} label="Antevon" current={current === 'antevon'} onClick={() => setCurrent('antevon')} />
      </Sidebar.Group>
      <Sidebar.Group id="pinned" label="pinned">
        {row('acme-forecast', 'acme-forecast', 'hash', { shared: true })}
        {row('supplier-outlook-file', 'Q4 supplier outlook', 'note')}
      </Sidebar.Group>
      <Sidebar.Group id="rooms" label="rooms">
        {row('fun', 'fun', 'hash')}
        {row('the-house', 'the house', 'hash')}
        {row('supplier-talks', 'supplier talks', 'hash')}
      </Sidebar.Group>
      <Sidebar.Group id="projects" label="projects">
        {row('hokuei', 'hokuei pilot', 'project', {
          childRows: [row('supplier-outlook', 'supplier outlook', 'hash'), row('kobe-deliveries', 'kobe deliveries', 'hash')],
        })}
        {row('personal', 'Personal', 'project')}
        {row('q4-planning', 'q4 planning', 'project')}
      </Sidebar.Group>
    </Sidebar>
  )
}

/* ── the microsidebar and the frame ──────────────────────────────────── */

interface PlaceFixture {
  id: string
  label: string
  icon: IconName
}

/* The places that are not fixed on the strip: they live in `more`, and
   the pinned ones also show under the divider. */
const MORE_PLACES: PlaceFixture[] = [
  { id: 'pipeline', label: 'pipeline', icon: 'lens' },
  { id: 'today', label: 'today', icon: 'calendar' },
  { id: 'notes', label: 'notes', icon: 'note' },
  { id: 'files', label: 'files', icon: 'files' },
  { id: 'people', label: 'people', icon: 'users' },
  { id: 'settings', label: 'settings', icon: 'gear' },
]

const PINNED_AT_START = ['pipeline', 'today', 'notes']

const placeOf = (id: string) => MORE_PLACES.find((l) => l.id === id)!

/* The first line of a sidebar inside the frame (inside Sidebar.Head):
   the place's name, search, a menu of what can be made here, and the fold
   control. */
function FrameHeadParts({ title }: { title: string }) {
  return (
    <>
      <span className="lib-sidebar-title">{title}</span>
      <IconAction label="Search" caption="press ⌘K">
        <Icon name="search" />
      </IconAction>
      <Menu>
        <Menu.Trigger asChild>
          <IconAction label="New" data-specimen="frame-new">
            <Icon name="plus" />
          </IconAction>
        </Menu.Trigger>
        <Menu.Content aria-label="new">
          <Menu.Item icon={<Icon name="hash" />}>a room</Menu.Item>
          <Menu.Item icon={<Icon name="project" />}>a project</Menu.Item>
        </Menu.Content>
      </Menu>
      <AppFrame.Fold />
    </>
  )
}

/* A short sidebar of rows, for the places that have one. */
function ListSidebar({
  title,
  rows,
}: {
  title: string
  rows: Array<{ id: string; label: string; icon?: IconName; glyph?: Resident; count?: number; caption?: string }>
}) {
  const [current, setCurrent] = React.useState(rows[0]?.id)
  return (
    <Sidebar aria-label={title}>
      <Sidebar.Head>
        <FrameHeadParts title={title} />
      </Sidebar.Head>
      <Sidebar.Group id="rows">
        {rows.map((r) => (
          <Sidebar.Row
            key={r.id}
            id={r.id}
            icon={r.icon ? <Icon name={r.icon} /> : undefined}
            glyph={r.glyph ? line(r.glyph) : undefined}
            label={r.label}
            caption={r.caption}
            count={r.count}
            current={current === r.id}
            onClick={() => setCurrent(r.id)}
          />
        ))}
      </Sidebar.Group>
    </Sidebar>
  )
}

/* Each place's sidebar; null for the places that have none (`more` is a
   menu, a lens is a page of its own). */
function sidebarFor(id: string, specimen: string): React.ReactNode | null {
  switch (id) {
    case 'home':
      return <HomeSidebar specimen={`${specimen}-home`} />
    case 'activity':
      return (
        <Sidebar aria-label="Activity">
          <Sidebar.Head>
            <FrameHeadParts title="Activity" />
          </Sidebar.Head>
          <ActivityCompactDemo specimen={`${specimen}-activity-compact`} readout={false} />
        </Sidebar>
      )
    case 'vault':
      return (
        <ListSidebar
          title="Vault"
          rows={[
            { id: 'ledger', label: 'ledger', icon: 'sheet' },
            { id: 'canvas', label: 'canvas', icon: 'canvas' },
            { id: 'connections', label: 'connections', icon: 'link' },
            { id: 'settings', label: 'settings', icon: 'gear' },
          ]}
        />
      )
    default:
      return null
  }
}

/* A whole microsidebar on fixture data: the vault's mark (home), activity
   with its count, the vault, more; the divider; the pinned lenses (they
   reorder and unpin); the person at the foot. Inside a frame the foot
   also holds the fold control, shown while the sidebar is folded. Alone,
   it stands on a window ground of its own with the readout under it. */
function MicroSidebarDemo({
  labels,
  current,
  onCurrent,
  inFrame = false,
  alone = false,
  waiting = false,
  specimen,
}: {
  labels?: 'none' | 'word'
  current: string
  onCurrent: (id: string) => void
  inFrame?: boolean
  alone?: boolean
  /* Activity waits on the person: the waiting ring under its count. */
  waiting?: boolean
  specimen?: string
}) {
  const [pinned, setPinned] = React.useState(PINNED_AT_START)
  const item = (id: string, label: string, icon: React.ReactNode, extra: { count?: number; needsYou?: boolean } = {}) => (
    <MicroSidebar.Item id={id} icon={icon} label={label} current={current === id} onClick={() => onCurrent(id)} {...extra} />
  )
  const strip = (
    <MicroSidebar labels={labels} aria-label={`places, ${labels ?? 'symbols'}`} data-specimen={specimen}>
      <MicroSidebar.VaultMark name="antevon" current={current === 'home'} onClick={() => onCurrent('home')} />
      {item('activity', 'activity', <Icon name="activity" />, { count: 3, needsYou: waiting })}
      {item('vault', 'vault', <Icon name="vault" />)}
      <MicroSidebar.More current={MORE_PLACES.some((m) => m.id === current) && !pinned.includes(current)}>
        {MORE_PLACES.map((m) => (
          <MicroSidebar.MoreItem
            key={m.id}
            icon={<Icon name={m.icon} />}
            label={m.label}
            pinned={pinned.includes(m.id)}
            onPinChange={(on) => setPinned((l) => (on ? [...l, m.id] : l.filter((x) => x !== m.id)))}
            onOpen={() => onCurrent(m.id)}
            data-place-id={m.id}
          />
        ))}
      </MicroSidebar.More>
      <MicroSidebar.Divider />
      <MicroSidebar.Pinned onReorder={setPinned}>
        {pinned.map((id) => {
          const place = placeOf(id)
          return (
            <MicroSidebar.Item
              key={id}
              id={id}
              icon={<Icon name={place.icon} />}
              label={place.label}
              current={current === id}
              onClick={() => onCurrent(id)}
              onUnpin={() => setPinned((l) => l.filter((x) => x !== id))}
            />
          )
        })}
      </MicroSidebar.Pinned>
      <MicroSidebar.Foot>
        {inFrame ? <AppFrame.Fold tooltipSide="right" /> : null}
        <Menu>
          <Menu.Trigger asChild>
            <MicroSidebar.Item id="you" icon={<Glyph initial="o" label="Owen" size={24} />} label="Owen" />
          </Menu.Trigger>
          <Menu.Content side="right" align="end" width="wide" aria-label="account">
            <AccountParts />
          </Menu.Content>
        </Menu>
      </MicroSidebar.Foot>
    </MicroSidebar>
  )
  return (
    <>
      {alone ? (
        <div className="lib-micro-stage">
          <WindowGround />
          {strip}
        </div>
      ) : (
        strip
      )}
      {specimen ? (
        <p className="lib-field-readout" data-specimen={`${specimen}-pinned`}>
          pinned {pinned.join(' ') || 'none'}, current {current}
          {pinned.join() !== PINNED_AT_START.join() ? (
            <button type="button" className="lib-pick lib-field-pick" onClick={() => setPinned(PINNED_AT_START)}>
              pin them back
            </button>
          ) : null}
        </p>
      ) : null}
    </>
  )
}

/* A microsidebar alone on the window ground of the page's theme. */
function MicroSidebarAlone({ labels, waiting, specimen }: { labels?: 'none' | 'word'; waiting?: boolean; specimen: string }) {
  const [current, setCurrent] = React.useState('home')
  return (
    <div className="lib-micro-demo">
      <MicroSidebarDemo labels={labels} waiting={waiting} current={current} onCurrent={setCurrent} specimen={specimen} alone />
    </div>
  )
}

/* The person's companion room in the work area: the head, the day's
   messages ending at the bottom, two asks in a needs-you card, and the
   write box. */
function RoomConversation({ specimen }: { specimen: string }) {
  const [sent, setSent] = React.useState<string[]>([])
  return (
    <div className="lib-room" data-specimen={specimen}>
      <PlaceHead icon={<Glyph glyph="wing" label="Eiri" size={24} />} title="eiri" />
      <div className="lib-room-trunk">
        <div className="lib-room-messages">
          <DayDivider>Today</DayDivider>
          <MessageRow author={<Glyph glyph="wing" label="Eiri" size={32} />} name="Eiri" time="09:02">
            <MessageRow.Text>Morning. Two things wait on you. Metryon finished the store pull overnight.</MessageRow.Text>
          </MessageRow>
          <NeedsYou aria-label="needs you" className="lib-room-asks">
            <NeedsYou.Item id="promo" asker={<Glyph glyph="ruler" label="Metryon" size={18} />} question="Should the fit treat weeks 44 to 46 as promo weeks?">
              <NeedsYou.Picks>
                <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
                <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
                <NeedsYou.Pick value="week-44">only week 44</NeedsYou.Pick>
                <NeedsYou.OwnAnswer />
                <NeedsYou.Later />
              </NeedsYou.Picks>
            </NeedsYou.Item>
            <NeedsYou.Item id="extracts" asker={<Glyph glyph="owl" label="Tory" size={18} />} question="Pull three paid registry extracts?">
              <NeedsYou.Picks>
                <NeedsYou.Pick value="allow" word="allowed once">
                  allow once
                </NeedsYou.Pick>
                <NeedsYou.Pick value="decline" word="declined" tone="consent">
                  decline
                </NeedsYou.Pick>
                <NeedsYou.Later />
              </NeedsYou.Picks>
            </NeedsYou.Item>
          </NeedsYou>
          <MessageRow author={<Glyph initial="o" label="Owen" size={32} />} name="Owen" time="09:10">
            <MessageRow.Text>Check the supplier notes against the filings.</MessageRow.Text>
          </MessageRow>
          <MessageRow author={<Glyph glyph="wing" label="Eiri" size={32} />} name="Eiri" time="09:10">
            <MessageRow.Text>I gave this to Tory.</MessageRow.Text>
          </MessageRow>
          {sent.map((text, i) => (
            <MessageRow key={i} author={<Glyph initial="o" label="Owen" size={32} />} name="Owen" time="just now">
              <MessageRow.Text>{text}</MessageRow.Text>
            </MessageRow>
          ))}
        </div>
      </div>
      <Composer
        className="lib-room-write"
        placeholder="Write to eiri"
        savedIn="Saved in your own vault"
        onSend={(text) => setSent((s) => [...s.slice(-2), text])}
      />
    </div>
  )
}

const PLACE_TITLE: Record<string, string> = { vault: 'vault', ...Object.fromEntries(MORE_PLACES.map((m) => [m.id, m.label])) }

/* The work area for the place on screen. */
function FrameWork({ place, specimen }: { place: string; specimen: string }) {
  if (place === 'home') return <RoomConversation specimen={`${specimen}-room`} />
  if (place === 'activity') {
    return (
      <div className="lib-frame-scroll">
        <div className="lib-frame-column">
          <ActivityDemo specimen={`${specimen}-activity`} />
        </div>
      </div>
    )
  }
  const lens = MORE_PLACES.find((m) => m.id === place)
  return (
    <div className="lib-frame-scroll">
      <div className="lib-frame-column">
        <PlaceHead icon={<Icon name={lens?.icon ?? 'vault'} />} title={PLACE_TITLE[place] ?? place} />
        <p className="lib-frame-line">Acme store sales by week, from the ledger.</p>
      </div>
    </div>
  )
}

/* The frame at 1100 x 620 in a bordered stage, inside a root of its own
   theme: the window ground, the microsidebar, the sheet. The current
   place sets the sidebar (none for a lens); folded, each place's sidebar
   peeks over the sheet. */
function FrameDemo({
  theme,
  defaultOpen = true,
  startAt = 'home',
  labels,
  specimen,
  caption,
}: {
  theme: LibraryTheme
  defaultOpen?: boolean
  startAt?: string
  labels?: 'none' | 'word'
  specimen: string
  caption: string
}) {
  const [current, setCurrent] = React.useState(startAt)
  const [open, setOpen] = React.useState(defaultOpen)
  const sidebar = sidebarFor(current, specimen)
  return (
    <figure className="lib-frame-specimen">
      <div className="lib-frame-scroller">
        <SafelightRoot theme={theme} className="lib-frame-root">
          <AppFrame
            className="lib-frame"
            data-specimen={specimen}
            microSidebar={<MicroSidebarDemo labels={labels} current={current} onCurrent={setCurrent} inFrame />}
            sidebar={sidebar}
            peek={(id) => sidebarFor(id, `${specimen}-peek`)}
            sidebarOpen={open}
            onSidebarOpenChange={setOpen}
          >
            <FrameWork place={current} specimen={specimen} />
          </AppFrame>
        </SafelightRoot>
      </div>
      <figcaption className="lib-field-caption">{caption}</figcaption>
      <p className="lib-field-readout" data-specimen={`${specimen}-state`}>
        sidebar {sidebar === null ? 'none' : open ? 'open' : 'folded'}, current {current}
      </p>
    </figure>
  )
}

/* ── sections ─────────────────────────────────────────────────────────── */

/* In the island: the parts that sit inside a well. */
export function FrameSections() {
  return (
    <>
      <Section title="VaultSwitch">
        <Specimen name="closed">
          <VaultSwitchDemo />
        </Specimen>
        <Specimen name="open: vaults, a new vault, then the account" tall={6} wide={1}>
          <VaultSwitchDemo defaultOpen specimen="vault-switch" />
        </Specimen>
      </Section>

      <Section title="PlaceHead">
        <Specimen name="a room: its symbol and title; the crew and actions at the right" full>
          <PlaceHeadDemo specimen="place-head" />
        </Specimen>
        <Specimen name="a task opened as a room: the origin line goes back" full>
          <PlaceHeadDemo specimen="place-head-origin" origin />
        </Specimen>
        <Specimen name="420 px: the right slot shrinks first, the title keeps every letter" full>
          <div className="lib-place-narrow" data-width="420">
            <PlaceHeadDemo specimen="place-head-420" origin title="fit the Q4 forecast for Acme stores" />
          </div>
        </Specimen>
        <Specimen name="220 px: the right slot is gone, then the title ends in an ellipsis" full>
          <div className="lib-place-narrow" data-width="220">
            <PlaceHeadDemo specimen="place-head-220" origin title="fit the Q4 forecast for Acme stores" />
          </div>
        </Specimen>
      </Section>

      <Section title="ActivityMark">
        {(['needs-you', 'running', 'mention', 'outside', 'done', 'reaction'] as const).map((kind) => (
          <Specimen key={kind} name={`${kind}: ${ACTIVITY_KIND_LABEL[kind]}`}>
            <ActivityMark kind={kind} data-specimen={`activity-mark-${kind}`} />
          </Specimen>
        ))}
      </Section>

      <Section title="ActivityList, ActivityRow, ActivityDay">
        <Specimen name="five slots; the open needs-you row takes the picks; older rows print fainter; a click selects a row" full>
          <ActivityDemo specimen="activity" />
        </Specimen>
        <Specimen name="compact, 230 px: two lines a row, the selected row lit; a needs-you row opens elsewhere" wide={1}>
          <ActivityCompactDemo specimen="activity-compact" />
        </Specimen>
      </Section>

      <Section title="SortCycle">
        <SortCycleSpecimen />
      </Section>

      <Section title="PeopleTable, RoleWord, RolePicker">
        <Specimen name="a tree of lead, team and agents; a guest with its origin; the role word opens the picker" full>
          <PeopleDemo />
        </Specimen>
        <Specimen name="the picker alone, read-only" wide={1}>
          <RolePicker roles={ROLES} defaultValue="steward" defaultActs={ACTS} canChange={false} />
        </Specimen>
      </Section>
    </>
  )
}

function SortCycleSpecimen() {
  const [sort, setSort] = React.useState('newest')
  return (
    <Specimen name="click to step through the orders; the tooltip names the one in force" wide={1}>
      <span className="lib-inline">
        <SortCycle options={SORTS} value={sort} onValueChange={setSort} data-specimen="sort-cycle" />
        <span className="lib-readout" data-specimen="sort-cycle-value">
          {SORTS.find((s) => s.value === sort)?.label}
        </span>
      </span>
    </Specimen>
  )
}

/* On the field: the sidebar alone, the microsidebar alone, then the app
   frame on each theme, open, folded with a peek, and with no sidebar. */
export function FieldSections() {
  const [collapsed, setCollapsed] = React.useState(true)
  return (
    <div className="lib-field-region">
      <section className="lib-field-section" aria-labelledby="lib-sidebar">
        <h2 id="lib-sidebar" className="lib-field-head">
          Sidebar
        </h2>
        <div className="lib-field-specimens">
          <figure className="lib-field-specimen">
            <SidebarDemo specimen="sidebar-reorder" />
            <figcaption className="lib-field-caption">
              drag a row or a group’s label, or press Alt with an arrow on it; pin a room on hover
            </figcaption>
          </figure>
          <figure className="lib-field-specimen">
            <SidebarDemo specimen="sidebar-collapsed" collapsed={collapsed} onCollapsedChange={setCollapsed} />
            <figcaption className="lib-field-caption">collapsed: symbols only, names in a tooltip</figcaption>
          </figure>
          <figure className="lib-field-specimen">
            <SidebarDemo specimen="sidebar-flat" childIndent="none" />
            <figcaption className="lib-field-caption">childIndent none: child rooms flush with their project, for comparison</figcaption>
          </figure>
        </div>
      </section>

      <section className="lib-field-section" aria-labelledby="lib-micro-sidebar">
        <h2 id="lib-micro-sidebar" className="lib-field-head">
          MicroSidebar
        </h2>
        <div className="lib-field-specimens">
          <figure className="lib-field-specimen">
            <MicroSidebarAlone specimen="micro-none" />
            <figcaption className="lib-field-caption">
              the vault’s mark first (home), then symbols, names in a tooltip; more lists the places off the strip, each with a pin toggle; drag a pinned place, or right-click it to unpin
            </figcaption>
          </figure>
          <figure className="lib-field-specimen">
            <MicroSidebarAlone labels="word" waiting specimen="micro-word" />
            <figcaption className="lib-field-caption">labels word: a word of at most eight letters under each symbol; activity waits on you</figcaption>
          </figure>
        </div>
      </section>

      <section className="lib-field-section" aria-labelledby="lib-frame-themes">
        <h2 id="lib-frame-themes" className="lib-field-head">
          frame, themes
        </h2>
        {GALLERY_THEMES.map((theme) => (
          <FrameDemo
            key={theme.id}
            theme={theme}
            specimen={`frame-${theme.id}`}
            caption={`${theme.label}${theme.kind === 'scene' ? ', a scene' : ''}: open; fold it with the control in the sidebar’s head or the [ key`}
          />
        ))}
        <FrameDemo
          theme={GALLERY_THEMES[0]}
          defaultOpen={false}
          specimen="frame-folded"
          caption="folded: rest the pointer on a place to see its sidebar raised over the sheet; move to the next place to switch"
        />
        <FrameDemo theme={GALLERY_THEMES[0]} startAt="notes" specimen="frame-no-sidebar" caption="a lens: no sidebar, the sheet is the work area alone" />
      </section>
    </div>
  )
}

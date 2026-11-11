import * as React from 'react'
import { applyTheme, readTheme, type Theme } from '~/components/safelight/hooks'
import {
  ActivityDay,
  ActivityList,
  ActivityRow,
  Glyph,
  Icon,
  IconAction,
  Island,
  Menu,
  NeedsYou,
  PeopleTable,
  Sidebar,
  RolePicker,
  RoleWord,
  SortCycle,
  StatusDot,
  VaultSwitch,
  Figure,
  type ActivityAge,
  type ActivityKind,
  type RoleAct,
  type RoleOption,
  type SortCycleOption,
  type VaultSwitchVault,
} from '~/design-system'
import { Section, Specimen } from './-gallery-frame'
import { ANTEVON, EIRI, METRYON, TORY, type Resident } from './-identity'

/* Frame sections of the /library gallery: the sidebar, the vault switch, the
   activity list, the sort cycle, the people table and its roles. Every demo
   works on fixture data from the app's cast. */

const line = (r: Resident, size: 18 | 24 = 18) => (
  <Glyph glyph={r.glyph} label={r.name} form="line" ink={r.ink} size={size} />
)

/* ── vaults and the account parts of the switch ───────────────────────── */

const VAULTS: VaultSwitchVault[] = [
  { id: 'antevon', name: 'antevon', caption: 'the house' },
  { id: 'Owen', name: 'Owen', caption: 'yours', needsYou: 2 },
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
      <PeopleTable.Row glyph={<Glyph initial="o" label="Owen" size={18} />} name="Owen" roleWord={<ReadOnlyRole id="owner" who="Owen" />}>
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
        roleWord={<ReadOnlyRole id="guest" who="Yuki" />}
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

/* A whole sidebar on fixture data: the head with the vault switch, the top
   rows, pinned, rooms, projects with nested rooms, and the vault. Rows and
   groups reorder; pinning moves a room between rooms and pinned. */
function SidebarDemo({
  ground,
  specimen,
  collapsed: collapsedProp,
  onCollapsedChange,
}: {
  ground: 'field' | 'paper'
  specimen: string
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
      setRooms((l) => [id, ...l])
    }
  }
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
        <Sidebar.Row id="hokuei" icon={<Icon name="project" />} label="hokuei pilot" current={current === 'hokuei'} onClick={() => setCurrent('hokuei')} />
        <Sidebar.Row id="outlook" depth={1} icon={<Icon name="hash" />} label="supplier outlook" current={current === 'outlook'} onClick={() => setCurrent('outlook')} />
        <Sidebar.Row id="contradictions" depth={2} icon={<Icon name="thread" />} label="supplier contradictions" current={current === 'contradictions'} onClick={() => setCurrent('contradictions')} />
        <Sidebar.Row id="personal" icon={<Icon name="project" />} label="Personal" current={current === 'personal'} onClick={() => setCurrent('personal')} />
        <Sidebar.Row id="passport" depth={1} icon={<Icon name="hash" />} label="passport" current={current === 'passport'} onClick={() => setCurrent('passport')} />
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
      <Sidebar ground={ground} collapsed={collapsed} onGroupReorder={setGroups} aria-label={`places, ${ground}`}>
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
        {groups.map((g) => part[g])}
      </Sidebar>
      <p className="lib-field-readout" data-specimen={`${specimen}-order`}>
        {groups.join(' ')} | {pinned.join(' ')} | {rooms.join(' ')}
      </p>
    </div>
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

      <Section title="ActivityList, ActivityRow, ActivityDay">
        <Specimen name="five slots; the open needs-you row takes the picks; older rows print fainter" full>
          <ActivityDemo specimen="activity" />
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

/* On the field: the sidebar alone, then the frame (a sidebar beside an island
   holding the activity list), on both grounds. */
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
            <SidebarDemo ground="field" specimen="sidebar-reorder" />
            <figcaption className="lib-field-caption">
              drag a row or a group’s label, or press Alt with an arrow on it; pin a room on hover
            </figcaption>
          </figure>
          <figure className="lib-field-specimen">
            <SidebarDemo ground="field" specimen="sidebar-collapsed" collapsed={collapsed} onCollapsedChange={setCollapsed} />
            <figcaption className="lib-field-caption">collapsed: symbols only, names in a tooltip</figcaption>
          </figure>
          <figure className="lib-field-specimen">
            <SidebarDemo ground="paper" specimen="sidebar-paper" />
            <figcaption className="lib-field-caption">on paper</figcaption>
          </figure>
        </div>
      </section>

      <section className="lib-field-section" aria-labelledby="lib-frame">
        <h2 id="lib-frame" className="lib-field-head">
          Frame
        </h2>
        {(['field', 'paper'] as const).map((ground) => (
          <figure key={ground} className="lib-frame-specimen">
            <div className="lib-frame" data-specimen={`frame-${ground}`}>
              <SidebarDemo ground={ground} specimen={`frame-${ground}-sidebar`} />
              <Island className="lib-frame-island">
                <ActivityDemo specimen={`frame-${ground}-activity`} />
              </Island>
            </div>
            <figcaption className="lib-field-caption">ground {ground}</figcaption>
          </figure>
        ))}
      </section>
    </div>
  )
}

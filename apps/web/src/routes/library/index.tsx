import { createFileRoute } from '@tanstack/react-router'
import * as React from 'react'
import { applyTheme, readTheme, type Theme } from '~/components/safelight/hooks'
import designSystemCss from '~/design-system/design-system.css?url'
import {
  Field,
  Figure,
  GuestRing,
  Glyph,
  ICON_NAMES,
  Icon,
  IconAction,
  Island,
  Menu,
  PickDiamond,
  Popover,
  Portrait,
  PrimaryButton,
  SafelightRoot,
  Seal,
  StatusDot,
  StepsBar,
  Tabs,
  Tooltip,
  Unfold,
  UrgencyMark,
  Verb,
  Well,
  type Step,
} from '~/design-system'
import { Section, Specimen } from './-gallery-frame'
import { RESIDENTS } from './-identity'
import { FieldSections, FrameSections } from './-frame'
import { PatternSections } from './-patterns'
import { TaskSections } from './-tasks'
import galleryCss from './-gallery.css?url'

export const Route = createFileRoute('/library/')({
  head: () => ({
    meta: [{ title: 'Safelight library' }],
    links: [
      { rel: 'stylesheet', href: designSystemCss },
      { rel: 'stylesheet', href: galleryCss },
    ],
  }),
  component: LibraryPage,
})

/* ── page frame ───────────────────────────────────────────────────────── */

/* The theme as three picks, drawn as circles: empty light, half system,
   full dark. Writes the same class on <html> as the app's theme switch. */
function ThemeGlyph({ theme }: { theme: Theme }) {
  return (
    <svg className="lib-theme-glyph" viewBox="0 0 12 12" aria-hidden="true">
      <circle cx="6" cy="6" r="4.6" data-fill={theme === 'dark' ? '' : undefined} />
      {theme === 'system' ? <path d="M6 1.4a4.6 4.6 0 0 1 0 9.2Z" /> : null}
    </svg>
  )
}

function ThemePicks() {
  const [theme, setTheme] = React.useState<Theme | null>(null)
  React.useEffect(() => setTheme(readTheme()), [])
  return (
    <div className="lib-theme" role="group" aria-label="theme">
      {(['light', 'system', 'dark'] as const).map((t) => (
        <button
          key={t}
          type="button"
          className="lib-theme-pick"
          aria-pressed={theme === t}
          onClick={() => {
            applyTheme(t)
            setTheme(t)
          }}
        >
          <ThemeGlyph theme={t} />
          {t}
        </button>
      ))}
    </div>
  )
}

/* ── fixtures ─────────────────────────────────────────────────────────── */

const RUN_STARTED: Step[] = [{ state: 'ahead' }, { state: 'ahead' }, { state: 'ahead' }]
const RUN_WORKING: Step[] = [{ state: 'done' }, { state: 'working', progress: 0.4 }, { state: 'ahead' }]
const RUN_WORKING_EARLY: Step[] = [{ state: 'done' }, { state: 'done' }, { state: 'working' }, { state: 'ahead' }]
const RUN_DONE: Step[] = [{ state: 'done' }, { state: 'done' }, { state: 'done' }]
const RUN_FAILED: Step[] = [{ state: 'done' }, { state: 'failed' }, { state: 'ahead' }]
const RUN_LONG_FAILED: Step[] = [
  ...Array.from({ length: 4 }, () => ({ state: 'done' as const })),
  { state: 'failed' },
  ...Array.from({ length: 5 }, () => ({ state: 'ahead' as const })),
]
const RUN_LONG: Step[] = [
  ...Array.from({ length: 6 }, () => ({ state: 'done' as const })),
  { state: 'working', progress: 0.5 },
  { state: 'ahead' },
  { state: 'ahead' },
  { state: 'ahead' },
]
const RUN_EIGHT: Step[] = [
  ...Array.from({ length: 5 }, () => ({ state: 'done' as const })),
  { state: 'working', progress: 0.7 },
  { state: 'ahead' },
  { state: 'ahead' },
]

const PICKS = ['promo weeks', 'normal weeks', 'only week 44']

function PickRow() {
  const [chosen, setChosen] = React.useState('normal weeks')
  return (
    <div className="lib-picks">
      {PICKS.map((p) => (
        <button key={p} type="button" className="lib-pick" aria-pressed={chosen === p} onClick={() => setChosen(p)}>
          <PickDiamond />
          {p}
        </button>
      ))}
    </div>
  )
}

/* ── the gallery ──────────────────────────────────────────────────────── */

function LibraryPage() {
  const [fieldRun, setFieldRun] = React.useState(0)
  const [persona, setPersona] = React.useState('all')

  return (
    <SafelightRoot className="lib">
      <Field key={fieldRun} />
      <header className="lib-head">
        <h1 className="lib-title">Safelight library</h1>
        <ThemePicks />
      </header>

      <Island className="lib-island">
        <Section title="SafelightRoot">
          <Specimen name="place">
            <span className="lib-t-place">acme-forecast</span>
          </Specimen>
          <Specimen name="section">
            <span className="lib-t-section">Threads</span>
          </Specimen>
          <Specimen name="say">
            <span className="lib-t-say">Should the fit treat weeks 44 to 46 as promo weeks?</span>
          </Specimen>
          <Specimen name="do">
            <span className="lib-t-do">later</span>
          </Specimen>
          <Specimen name="figure">
            <Figure>31 min ago</Figure>
          </Specimen>
          <Specimen name="badge">
            <Figure size="badge">20</Figure>
          </Specimen>
        </Section>

        <Section title="Field">
          <Specimen name="develops on load">
            <Verb onClick={() => setFieldRun((n) => n + 1)}>develop again</Verb>
          </Specimen>
        </Section>

        <Section title="Island">
          <Specimen name="grain">
            <Well className="lib-island-host">
              <Island className="lib-island-small">
                <span className="lib-t-say">Hokuei pilot</span>
              </Island>
            </Well>
          </Specimen>
          <Specimen name="no grain">
            <Well className="lib-island-host">
              <Island className="lib-island-small" grain={false}>
                <span className="lib-t-say">Hokuei pilot</span>
              </Island>
            </Well>
          </Specimen>
        </Section>

        <Section title="Well">
          <Specimen name="sunk">
            <Well className="lib-well">
              <span className="lib-t-say">Acme’s week 44 dip comes back every year</span>
            </Well>
          </Specimen>
          <Specimen name="island tone on sunk">
            <Well className="lib-well">
              <Well tone="island" className="lib-well">
                <span className="lib-t-say">Edit Acme store sales</span>
              </Well>
            </Well>
          </Specimen>
        </Section>

        <Section title="Verb">
          <Specimen name="plain">
            <Verb>later</Verb>
          </Specimen>
          <Specimen name="consent">
            <Verb tone="consent" data-specimen="consent">
              disconnect
            </Verb>
          </Specimen>
          <Specimen name="expanded">
            <Verb aria-expanded="true">show all</Verb>
          </Specimen>
          <Specimen name="disabled">
            <Verb disabled>undo</Verb>
          </Specimen>
        </Section>

        <Section title="IconAction">
          <Specimen name="name and caption">
            <IconAction label="Search" caption="press ⌘K" data-specimen="icon-action">
              <Icon name="search" />
            </IconAction>
          </Specimen>
          <Specimen name="small">
            <IconAction label="More" size="sm">
              <Icon name="more" />
            </IconAction>
          </Specimen>
          <Specimen name="pressed">
            <IconAction label="Pin" aria-pressed="true">
              <Icon name="pin" />
            </IconAction>
          </Specimen>
          <Specimen name="expanded">
            <IconAction label="Reply" aria-expanded="true">
              <Icon name="reply" />
            </IconAction>
          </Specimen>
          <Specimen name="consent">
            <IconAction label="Disconnect" tone="consent">
              <Icon name="x" />
            </IconAction>
          </Specimen>
          <Specimen name="disabled">
            <IconAction label="Attach" disabled>
              <Icon name="clip" />
            </IconAction>
          </Specimen>
        </Section>

        <Section title="PrimaryButton">
          <Specimen name="rest">
            <PrimaryButton>Send</PrimaryButton>
          </Specimen>
          <Specimen name="disabled">
            <PrimaryButton disabled>Send</PrimaryButton>
          </Specimen>
        </Section>

        <Section title="Figure">
          <Specimen name="count">
            <Figure>214</Figure>
          </Specimen>
          <Specimen name="time">
            <Figure as="time" dateTime="14:02">
              14:02
            </Figure>
          </Specimen>
          <Specimen name="elapsed">
            <Figure>4m14s</Figure>
          </Specimen>
          <Specimen name="badge">
            <Figure size="badge">20</Figure>
          </Specimen>
        </Section>

        <Section title="Icon">
          <Specimen name="every symbol, by name" full>
            <ul className="lib-icons" data-specimen="icons">
              {ICON_NAMES.map((name) => (
                <li key={name} className="lib-icon">
                  <Icon name={name} size={18} />
                  <span className="lib-icon-name">{name}</span>
                </li>
              ))}
            </ul>
          </Specimen>
        </Section>

        <Section title="Tabs">
          <Specimen name="first selected, a count" wide={1}>
            <Tabs defaultValue="messages" className="lib-tabs">
              <Tabs.List aria-label="room views">
                <Tabs.Tab value="messages">messages</Tabs.Tab>
                <Tabs.Tab value="files" count={2}>
                  files
                </Tabs.Tab>
                <Tabs.Tab value="canvas">canvas</Tabs.Tab>
              </Tabs.List>
              <Tabs.Panel value="messages" className="lib-panel">
                Metryon started on the Q4 view.
              </Tabs.Panel>
              <Tabs.Panel value="files" className="lib-panel">
                Acme store sales, Hokuei brief.
              </Tabs.Panel>
              <Tabs.Panel value="canvas" className="lib-panel">
                The vault canvas for this room.
              </Tabs.Panel>
            </Tabs>
          </Specimen>
          <Specimen name="last selected" wide={1}>
            <Tabs defaultValue="mentions" className="lib-tabs">
              <Tabs.List aria-label="activity views">
                <Tabs.Tab value="threads" count={3}>
                  threads
                </Tabs.Tab>
                <Tabs.Tab value="reactions" count={4}>
                  reactions
                </Tabs.Tab>
                <Tabs.Tab value="mentions" count={3}>
                  mentions
                </Tabs.Tab>
              </Tabs.List>
            </Tabs>
          </Specimen>
        </Section>

        <Section title="Unfold">
          <Specimen name="closed" wide={1}>
            <Unfold className="lib-unfold">
              <Unfold.Trigger asChild>
                <Verb>show the plan</Verb>
              </Unfold.Trigger>
              <Unfold.Content>
                <ol className="lib-plan">
                  <li>pull Acme sales</li>
                  <li>summarise the sources</li>
                  <li>fit the forecast</li>
                </ol>
              </Unfold.Content>
            </Unfold>
          </Specimen>
          <Specimen name="open" wide={1}>
            <Unfold defaultOpen className="lib-unfold">
              <Unfold.Trigger asChild>
                <Verb>show the plan</Verb>
              </Unfold.Trigger>
              <Unfold.Content>
                <ol className="lib-plan">
                  <li>pull Acme sales</li>
                  <li>summarise the sources</li>
                  <li>fit the forecast</li>
                </ol>
              </Unfold.Content>
            </Unfold>
          </Specimen>
        </Section>

        <Section title="Tooltip">
          <Specimen name="name and caption" tall={1} wide={1}>
            <Tooltip defaultOpen align="start" label="Metryon" caption="fitting the Q4 forecast for Acme">
              <Verb>Metryon</Verb>
            </Tooltip>
          </Specimen>
          <Specimen name="plain hint" tall={1} wide={1}>
            <Tooltip defaultOpen align="start" label="Everyone in the room">
              <Verb>everyone</Verb>
            </Tooltip>
          </Specimen>
        </Section>

        <Section title="Popover">
          <Specimen name="closed">
            <Popover>
              <Popover.Trigger asChild>
                <Verb>Tory</Verb>
              </Popover.Trigger>
              <Popover.Content className="lib-crew-pop" aria-label="Tory">
                <CrewCard glyph="owl" name="Tory" line="checking the May filings" />
              </Popover.Content>
            </Popover>
          </Specimen>
          <Specimen name="open" tall={2}>
            <Popover defaultOpen>
              <Popover.Trigger asChild>
                <Verb>Metryon</Verb>
              </Popover.Trigger>
              <Popover.Content className="lib-crew-pop" aria-label="Metryon">
                <CrewCard glyph="ruler" name="Metryon" line="fitting the Q4 forecast for Acme" />
              </Popover.Content>
            </Popover>
          </Specimen>
        </Section>

        <Section title="Menu">
          <Specimen name="open" tall={4}>
            <Menu defaultOpen>
              <Menu.Trigger asChild>
                <Verb>Owen</Verb>
              </Menu.Trigger>
              <Menu.Content width="wide" aria-label="account">
                <Menu.Heading>Personas</Menu.Heading>
                {['all', 'work', 'personal'].map((p) => (
                  <Menu.Item
                    key={p}
                    checked={persona === p}
                    closeOnSelect={false}
                    onClick={() => setPersona(p)}
                    icon={<Glyph initial="o" label={`Owen, ${p}`} size={18} className="lib-menu-glyph" />}
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
                <Menu.Separator />
                <Menu.Item icon={<Icon name="signOut" />}>sign out</Menu.Item>
              </Menu.Content>
            </Menu>
          </Specimen>
          <Specimen name="closed">
            <Menu>
              <Menu.Trigger asChild>
                <IconAction label="More">
                  <Icon name="more" />
                </IconAction>
              </Menu.Trigger>
              <Menu.Content>
                <Menu.Item icon={<Icon name="reply" />}>quote in a reply</Menu.Item>
                <Menu.Item icon={<Icon name="link" />}>copy the link</Menu.Item>
              </Menu.Content>
            </Menu>
          </Specimen>
        </Section>

        <Section title="PickDiamond">
          <Specimen name="rest">
            <PickDiamond />
          </Specimen>
          <Specimen name="chosen">
            <PickDiamond chosen />
          </Specimen>
          <Specimen name="in picks" wide={1}>
            <PickRow />
          </Specimen>
        </Section>

        <Section title="StatusDot">
          <Specimen name="live">
            <StatusDot state="live" />
          </Specimen>
          <Specimen name="approved">
            <StatusDot state="approved" />
          </Specimen>
          <Specimen name="proposed">
            <StatusDot state="proposed" />
          </Specimen>
          <Specimen name="idle">
            <StatusDot state="idle" />
          </Specimen>
        </Section>

        <Section title="GuestRing">
          <Specimen name="after a count">
            <span className="lib-inline">
              <span className="lib-t-do">shared with Acme’s vault</span>
              <span className="lib-count">
                <GuestRing label="guests" />
                <Figure>2</Figure>
              </span>
            </span>
          </Specimen>
          <Specimen name="at a glyph">
            <Glyph initial="y" label="Yuki" guest />
          </Specimen>
        </Section>

        <Section title="Seal">
          <Specimen name="person">
            <Seal by="person" />
          </Specimen>
          <Specimen name="agent">
            <Seal by="agent" />
          </Specimen>
          <Specimen name="system">
            <Seal by="system" />
          </Specimen>
          <Specimen name="person 16">
            <Seal by="person" size={16} />
          </Specimen>
          <Specimen name="agent 16">
            <Seal by="agent" size={16} />
          </Specimen>
          <Specimen name="system 16">
            <Seal by="system" size={16} />
          </Specimen>
        </Section>

        <Section title="UrgencyMark">
          <Specimen name="mark">
            <UrgencyMark />
          </Specimen>
          <Specimen name="with a reason">
            <UrgencyMark>blocks the fit</UrgencyMark>
          </Specimen>
          <Specimen name="with a deadline">
            <UrgencyMark>
              due Friday <Figure>17:00</Figure>
            </UrgencyMark>
          </Specimen>
        </Section>

        <Section title="StepsBar">
          <Specimen name="not started">
            <StepsBar steps={RUN_STARTED} />
          </Specimen>
          <Specimen name="working, 0.4">
            <StepsBar steps={RUN_WORKING} />
          </Specimen>
          <Specimen name="working, no sub-steps">
            <StepsBar steps={RUN_WORKING_EARLY} />
          </Specimen>
          <Specimen name="done">
            <StepsBar steps={RUN_DONE} />
          </Specimen>
          <Specimen name="failed">
            <StepsBar steps={RUN_FAILED} />
          </Specimen>
          <Specimen name="ten steps, failed">
            <StepsBar steps={RUN_LONG_FAILED} />
          </Specimen>
          <Specimen name="eight steps">
            <StepsBar steps={RUN_EIGHT} />
          </Specimen>
          <Specimen name="ten steps, fixed cells">
            <StepsBar steps={RUN_LONG} />
          </Specimen>
        </Section>

        <Section title="Glyph">
          <Specimen name="Eiri">
            <Glyph glyph="wing" label="Eiri" size={32} />
          </Specimen>
          <Specimen name="Tory">
            <Glyph glyph="owl" label="Tory" size={32} />
          </Specimen>
          <Specimen name="Antevon">
            <Glyph glyph="laurel" label="Antevon" size={32} />
          </Specimen>
          <Specimen name="Metryon">
            <Glyph glyph="ruler" label="Metryon" size={32} />
          </Specimen>
          <Specimen name="Owen">
            <Glyph initial="o" label="Owen" size={32} />
          </Specimen>
          <Specimen name="18, 24, 32">
            <span className="lib-inline">
              <Glyph glyph="ruler" label="Metryon" size={18} />
              <Glyph glyph="ruler" label="Metryon" size={24} />
              <Glyph glyph="ruler" label="Metryon" size={32} />
              <Glyph initial="y" label="Yuki" size={18} />
              <Glyph initial="y" label="Yuki" size={24} />
              <Glyph initial="y" label="Yuki" size={32} />
            </span>
          </Specimen>
          <Specimen name="square, rounded, round">
            <span className="lib-inline">
              <Glyph glyph="owl" label="Tory" shape="square" />
              <Glyph glyph="owl" label="Tory" shape="rounded" />
              <Glyph glyph="owl" label="Tory" shape="round" />
              <Glyph initial="o" label="Owen" shape="square" />
              <Glyph initial="o" label="Owen" shape="rounded" />
              <Glyph initial="o" label="Owen" shape="round" />
            </span>
          </Specimen>
          <Specimen name="idle, working, waiting, done">
            <span className="lib-inline lib-inline-wide">
              <Glyph glyph="laurel" label="Antevon" state="idle" />
              <Glyph glyph="ruler" label="Metryon" state="working" />
              <Glyph glyph="wing" label="Eiri" state="waiting" />
              <Glyph glyph="owl" label="Tory" state="done" />
              <Glyph initial="o" label="Owen" state="idle" />
              <Glyph initial="y" label="Yuki" state="working" />
              <Glyph initial="o" label="Owen" state="waiting" />
              <Glyph initial="y" label="Yuki" state="done" />
            </span>
          </Specimen>
          <Specimen name="guest">
            <span className="lib-inline lib-inline-wide">
              <Glyph glyph="wing" label="Eiri" guest />
              <Glyph initial="y" label="Yuki" guest state="working" />
            </span>
          </Specimen>
          <Specimen name="line, in each resident's ink">
            <span className="lib-inline lib-inline-wide">
              {RESIDENTS.map((r) => (
                <Glyph key={r.name} glyph={r.glyph} label={r.name} form="line" ink={r.ink} size={32} />
              ))}
              <Glyph initial="o" label="Owen" form="line" size={32} />
            </span>
          </Specimen>
          <Specimen name="line, no ink">
            <span className="lib-inline lib-inline-wide">
              <Glyph glyph="moon" label="moon" form="line" size={32} />
              <Glyph glyph="laurel" label="laurel" form="line" size={32} />
            </span>
          </Specimen>
          <Specimen name="line at 18, 24, 32">
            <span className="lib-inline">
              {([18, 24, 32] as const).map((size) => (
                <Glyph key={size} glyph="wing" label="Eiri" form="line" ink={RESIDENTS[0].ink} size={size} />
              ))}
              {([18, 24, 32] as const).map((size) => (
                <Glyph key={`o${size}`} glyph="owl" label="Tory" form="line" ink={RESIDENTS[1].ink} size={size} />
              ))}
            </span>
          </Specimen>
          <Specimen name="line, states and guest">
            <span className="lib-inline lib-inline-wide">
              <Glyph glyph="laurel" label="Antevon" form="line" ink={RESIDENTS[2].ink} state="idle" />
              <Glyph glyph="ruler" label="Metryon" form="line" ink={RESIDENTS[3].ink} state="working" />
              <Glyph glyph="wing" label="Eiri" form="line" ink={RESIDENTS[0].ink} state="waiting" />
              <Glyph glyph="owl" label="Tory" form="line" ink={RESIDENTS[1].ink} state="done" />
              <Glyph glyph="wing" label="Eiri" form="line" ink={RESIDENTS[0].ink} guest />
            </span>
          </Specimen>
          <Specimen name="seal in a resident's ink">
            <span className="lib-inline lib-inline-wide">
              {RESIDENTS.map((r) => (
                <Glyph key={r.name} glyph={r.glyph} label={r.name} ink={r.ink} size={32} />
              ))}
            </span>
          </Specimen>
        </Section>

        <Section title="Portrait">
          <Specimen name="profile, Eiri">
            <Portrait glyph="wing" label="Eiri" />
          </Specimen>
          <Specimen name="profile, Owen">
            <Portrait initial="o" label="Owen" />
          </Specimen>
          <Specimen name="stack">
            <span className="lib-inline">
              <Portrait glyph="ruler" label="Metryon" size="stack" />
              <Portrait glyph="owl" label="Tory" size="stack" />
              <Portrait glyph="laurel" label="Antevon" size="stack" />
              <Portrait initial="y" label="Yuki" size="stack" />
            </span>
          </Specimen>
          <Specimen name="stack, guest">
            <Portrait initial="y" label="Yuki" size="stack" guest />
          </Specimen>
        </Section>

        <PatternSections />
        <TaskSections />
        <FrameSections />
      </Island>
      <FieldSections />
    </SafelightRoot>
  )
}

/* The head of a crew popover: the portrait, the name, what the resident is
   doing, and the one verb. */
function CrewCard({ glyph, name, line }: { glyph: 'owl' | 'ruler'; name: string; line: string }) {
  return (
    <div className="lib-crew">
      <Portrait glyph={glyph} label={name} size="stack" />
      <div className="lib-crew-who">
        <span className="lib-crew-name">{name}</span>
        <span className="lib-crew-line">{line}</span>
      </div>
      <Verb>open the profile</Verb>
    </div>
  )
}

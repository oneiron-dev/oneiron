import * as React from 'react'
import {
  CrewStack,
  DayDivider,
  FileRow,
  Glyph,
  Icon,
  IconAction,
  MessageRow,
  PinMark,
  PinnedList,
  RoomHead,
  ROOM_VIEWS,
  SafelightRoot,
  Tabs,
  type IconName,
  type RoomPins,
} from '~/design-system'
import { ChartCard } from './-cards'
import { GALLERY_THEMES } from './-themes'

/* The head line of a room in its three forms, at two widths, and the
   lists behind its tabs: a room of the cast with its pins, its files and
   its crew. Every tab works; the readout under each says what happened. */

const PIN_MARK = <PinMark />

const FILES: Array<{ kind: IconName; name: string; who: React.ReactNode; author: string; time: string; pinned?: boolean }> = [
  { kind: 'chart', name: 'Q4 view', who: <Glyph glyph="ruler" label="Metryon" size={18} />, author: 'Metryon', time: '14:31', pinned: true },
  { kind: 'table', name: 'Stores in the pilot', who: <Glyph glyph="ruler" label="Metryon" size={18} />, author: 'Metryon', time: '14:20' },
  { kind: 'table', name: 'Acme store sales', who: <Glyph glyph="owl" label="Tory" size={18} />, author: 'Tory', time: '09:40' },
  { kind: 'note', name: 'The brief', who: <Glyph glyph="laurel" label="Antevon" size={18} />, author: 'Antevon', time: '9 Nov', pinned: true },
  { kind: 'note', name: 'Supplier notes', who: <Glyph glyph="laurel" label="Antevon" size={18} />, author: 'Antevon', time: '9 Nov' },
  { kind: 'deck', name: 'Q3 review', who: <Glyph initial="y" label="Yuki" size={18} guest />, author: 'Yuki', time: '2 Nov' },
]

const PINNED_MESSAGE = 'Can we have the Q4 view by Friday?'

function Crew() {
  return (
    <CrewStack aria-label="crew of # acme-forecast">
      <CrewStack.Member name="Owen, you" caption="here now">
        <Glyph initial="o" label="Owen" />
      </CrewStack.Member>
      <CrewStack.Member name="Yuki, a guest" caption="from Acme’s vault, reads and proposes">
        <Glyph initial="y" label="Yuki" guest />
      </CrewStack.Member>
      <CrewStack.Member name="Metryon" caption="fitting the Q4 forecast for Acme">
        <Glyph glyph="ruler" label="Metryon" size={18} />
      </CrewStack.Member>
      <CrewStack.Member name="Tory" caption="pulled Acme store sales">
        <Glyph glyph="owl" label="Tory" size={18} />
      </CrewStack.Member>
      <CrewStack.Member name="Antevon" caption="keeping the record">
        <Glyph glyph="laurel" label="Antevon" size={18} />
      </CrewStack.Member>
    </CrewStack>
  )
}

/* The view a tab selects. */
function RoomView({ view, marked, onLog }: { view: string; marked: boolean; onLog: (line: string) => void }) {
  if (view === ROOM_VIEWS.files) {
    return (
      <FileRow.List data-specimen="room-files">
        {FILES.map((f) => (
          <FileRow
            key={f.name}
            kind={f.kind}
            kindLabel={f.kind}
            name={f.name}
            pinned={f.pinned}
            portrait={f.who}
            author={f.author}
            time={f.time}
            onOpen={() => onLog(`opens ${f.name} beside the list`)}
          />
        ))}
      </FileRow.List>
    )
  }
  if (view === ROOM_VIEWS.pinned) {
    return (
      <PinnedList data-specimen="room-pinned">
        <FileRow kind="chart" kindLabel="chart" name="Q4 view" portrait={<Glyph glyph="ruler" label="Metryon" size={18} />} author="Metryon" time="14:31" onOpen={() => onLog('opens Q4 view')} />
        <FileRow kind="note" kindLabel="note" name="The brief" portrait={<Glyph glyph="laurel" label="Antevon" size={18} />} author="Antevon" time="9 Nov" onOpen={() => onLog('opens The brief')} />
        <FileRow
          mark={<Glyph initial="y" label="Yuki" size={18} guest />}
          name={PINNED_MESSAGE}
          portrait={<Glyph initial="o" label="Owen" size={18} />}
          author="Owen"
          time="13:52"
          onOpen={() => onLog('goes to the message')}
        />
      </PinnedList>
    )
  }
  if (view === 'q4') {
    return (
      <div className="lib-messages">
        <MessageRow
          author={<Glyph glyph="ruler" label="Metryon" size={24} />}
          name="Metryon"
          time="14:31"
          marks={
            <>
              {PIN_MARK}
              <IconAction label="Open beside the talk" size="sm" onClick={() => onLog('opens Q4 view beside the talk')}>
                <Icon name="pane" />
              </IconAction>
            </>
          }
        >
          <ChartCard bare specimen="room-q4" />
        </MessageRow>
      </div>
    )
  }
  if (view === 'brief') {
    return (
      <div className="lib-messages">
        <MessageRow author={<Glyph glyph="laurel" label="Antevon" size={24} />} name="Antevon" time="9 Nov" marks={PIN_MARK}>
          <MessageRow.Text>Acme wants one Q4 sales view by store: 214 stores, weekly, by Friday 13 November.</MessageRow.Text>
          <MessageRow.Text>Weeks 44 to 46 dip every year. Ask before you treat them as promo weeks.</MessageRow.Text>
        </MessageRow>
      </div>
    )
  }
  return (
    <div className="lib-messages">
      <DayDivider>Today</DayDivider>
      <MessageRow author={<Glyph initial="y" label="Yuki" size={24} guest />} name="Yuki" time="13:50" marked={marked} marks={PIN_MARK}>
        <MessageRow.Text>{PINNED_MESSAGE}</MessageRow.Text>
      </MessageRow>
    </div>
  )
}

/* One room on a stage of a set width: its head line, then the view its
   tab selects. */
function RoomDemo({ pins, width, defaultView = ROOM_VIEWS.talk, specimen, caption }: { pins: RoomPins; width: number; defaultView?: string; specimen: string; caption: string }) {
  const [view, setView] = React.useState(defaultView)
  const [log, setLog] = React.useState('')
  const [marked, setMarked] = React.useState(false)
  const [outline, setOutline] = React.useState(false)
  React.useEffect(() => {
    if (!marked) return
    const timer = setTimeout(() => setMarked(false), 1800)
    return () => clearTimeout(timer)
  }, [marked])
  /* Three fixed tabs: a pinned view shows the pinned list. */
  const shown = pins === 'tab' && (view === 'q4' || view === 'brief') ? ROOM_VIEWS.pinned : pins === 'none' ? ROOM_VIEWS.talk : view
  return (
    <figure className="lib-frame-specimen">
      <div className="lib-frame-scroller">
        <SafelightRoot theme={GALLERY_THEMES[0]} className="lib-room-root" style={{ width }} data-specimen={specimen}>
          <Tabs value={shown} onValueChange={setView} className="lib-room-stage">
            <RoomHead
              title="acme-forecast"
              pins={pins}
              filesCount={FILES.length}
              tasks={['done', 'working', 'ahead']}
              tasksNeedYou
              onOpenTasks={() => setLog('the tasks open in the pane')}
              crew={<Crew />}
              outlineOpen={outline}
              onOpenOutline={() => {
                setOutline((o) => !o)
                setLog(outline ? 'outline closed' : 'the outline opens in the pane')
              }}
              onAddPin={() => setLog('pick a message, a file or a lens to pin')}
            >
              <Tabs.Pin value="q4" icon="chart" pinnedBy="Metryon">
                Q4 view
              </Tabs.Pin>
              <Tabs.Pin value="brief" icon="note" pinnedBy="Antevon">
                The brief
              </Tabs.Pin>
              <Tabs.Pin
                onGo={() => {
                  setView(ROOM_VIEWS.talk)
                  setMarked(true)
                  setLog('went to the message')
                }}
                mark={<Glyph initial="y" label="Yuki" size={16} />}
                pinnedBy="Owen"
              >
                {PINNED_MESSAGE}
              </Tabs.Pin>
            </RoomHead>
            <div className="lib-room-view">
              <RoomView view={shown} marked={marked} onLog={setLog} />
            </div>
          </Tabs>
        </SafelightRoot>
      </div>
      <figcaption className="lib-field-caption lib-room-caption">{caption}</figcaption>
      <p className="lib-field-readout lib-room-caption" data-specimen={`${specimen}-state`}>
        view {shown}
        {log ? `, ${log}` : ''}
      </p>
    </figure>
  )
}

export function RoomHeadSection() {
  return (
    <section className="lib-field-section" aria-labelledby="lib-room-head">
      <h2 id="lib-room-head" className="lib-field-head">
        RoomHead: the head line of a room, and the lists behind its tabs
      </h2>
      <RoomDemo pins="head" width={1100} specimen="room-head-1100" caption="pins on the head line, 1100 wide: talk, files, then the room’s pins and add; a pinned message goes to the message and is never selected" />
      <RoomDemo pins="head" width={700} specimen="room-head-700" caption="pins on the head line, 700 wide: the pins, the divider and add fold into one tab with the pin and a count" />
      <RoomDemo pins="head" width={480} specimen="room-head-480" caption="480 wide: the crew hides before the name loses a letter" />
      <RoomDemo pins="tab" width={1100} specimen="room-tab-1100" caption="three fixed tabs, 1100 wide: talk, files, pinned" />
      <RoomDemo pins="tab" width={700} specimen="room-tab-700" caption="three fixed tabs, 700 wide" />
      <RoomDemo pins="none" width={1100} specimen="room-none-1100" caption="no tabs, 1100 wide: the outline action at the right opens the outline; no tasks donut" />
      <RoomDemo pins="none" width={700} specimen="room-none-700" caption="no tabs, 700 wide" />
      <RoomDemo pins="head" width={1100} defaultView={ROOM_VIEWS.files} specimen="room-files-1100" caption="the files of the room: kind, name, a pin mark, who made it, when it changed; a row opens the file beside the list" />
      <RoomDemo pins="tab" width={1100} defaultView={ROOM_VIEWS.pinned} specimen="room-pinned-1100" caption="the pinned list: a row opens the thing, or goes to the message" />
      <RoomDemo pins="head" width={1100} defaultView="q4" specimen="room-q4-1100" caption="a pinned thing as a view of the room: the chart card bare, its note under it" />
    </section>
  )
}

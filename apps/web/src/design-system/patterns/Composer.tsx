import * as React from 'react'
import { Icon, type IconName } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { PrimaryButton } from '../primitives/PrimaryButton'
import { Verb } from '../primitives/Verb'
import { Menu } from '../overlays/Menu'
import { Tooltip } from '../overlays/Tooltip'
import { cx, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { composerKeySends, composerSendText } from './composer-keys'
import { findBoostWord } from './find-boost-word'

/* The field grows with its text up to this height, then scrolls. */
const FIELD_MAX_PX = 220

export interface ComposerSendDetails {
  /* The text held a boost word and the person left the boost on. */
  boost: boolean
}

export type ComposerSize = 'default' | 'small'
export type ComposerTools = 'always' | 'on focus'

export interface ComposerProps extends Omit<React.ComponentPropsWithRef<'form'>, 'onSubmit' | 'defaultValue'> {
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
  /* Called with the trimmed text on Send and on Enter. Empty text does not
     send. */
  onSend?: (text: string, details: ComposerSendDetails) => void
  placeholder?: string
  /* `default` writes to a room or a companion: the writer's portrait in
     the gutter, a box that grows with the text. `small` writes in a pane
     or about one thing: 40 px high, one line, no portrait. */
  size?: ComposerSize
  /* Small only. `always`: the add action at the left, dictation and the
     button at the right. `on focus` (the default for small): only the
     field at rest; on focus or with text the add action, dictation and
     the button show at the right, so the text never moves. */
  tools?: ComposerTools
  /* The writer's portrait (a Composer.Persona), in the gutter at the left
     of the box. Default size only. */
  persona?: React.ReactNode
  /* The one line above the box when what is sent crosses a boundary: an
     OutsideLine. */
  crossing?: React.ReactNode
  /* Further tool icons at the right of the field, before dictation. */
  actions?: React.ReactNode
  /* Shows the dictate action: dictation into the field. */
  onDictate?: () => void
  /* Default size: while the field is empty, the button shows the voice
     mark and calls this. */
  onVoice?: () => void
  sendLabel?: string
  voiceLabel?: string
  /* The field's accessible name; the placeholder by default. */
  fieldLabel?: string
  /* Words that ask for more thought on a message. While the text holds one
     as a whole word, a quiet line says so, with `do not` to turn it off
     until the text changes. */
  boostWords?: readonly string[]
  onBoostChange?: (boost: boolean) => void
}

/* The write box. Above the box: the crossing line, then Composer.Carry
   with quoted pointers and attached chips; a Composer.Add among the
   children sits in the box instead. Default size: the writer's portrait in
   a 24 px gutter, then the box in the messages column (fully rounded
   ends, the sunk tone, a 1 px inset hairline): add, the field (it grows to
   several lines), the tool icons, dictation, and one round filled button
   (the voice mark while the field is empty, the send arrow with text).
   Small: one 40 px line with a 30 px send button. Enter sends,
   Shift+Enter starts a new line in the default box, Escape leaves the
   field; an empty send puts focus in the field. */
function ComposerRoot({
  ref,
  value: valueProp,
  defaultValue = '',
  onValueChange,
  onSend,
  placeholder = 'Write a message',
  size = 'default',
  tools: toolsProp,
  persona,
  crossing,
  actions,
  onDictate,
  onVoice,
  sendLabel = 'Send',
  voiceLabel = 'Talk',
  fieldLabel,
  boostWords,
  onBoostChange,
  className,
  children,
  ...props
}: ComposerProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  const small = size === 'small'
  const tools: ComposerTools = small ? (toolsProp ?? 'on focus') : 'always'
  const fieldRef = React.useRef<HTMLTextAreaElement | HTMLInputElement | null>(null)

  /* Grow with the text: measure at auto height, keep within the maximum.
     Empty, the field is one line. The small field is one line always. */
  useIsomorphicLayoutEffect(() => {
    const field = fieldRef.current
    if (!field || small) return
    if (!value) {
      field.style.height = ''
      field.style.overflowY = 'hidden'
      return
    }
    field.style.height = 'auto'
    const next = Math.min(field.scrollHeight, FIELD_MAX_PX)
    field.style.height = `${next}px`
    field.style.overflowY = field.scrollHeight > FIELD_MAX_PX ? 'auto' : 'hidden'
  }, [value, small])

  /* The boost: on while a boost word stands in the text, unless the person
     turned it off for exactly this text. */
  const [declinedFor, setDeclinedFor] = React.useState<string | null>(null)
  const boostWord = boostWords?.length ? findBoostWord(value, boostWords) : null
  const boost = boostWord !== null && declinedFor !== value
  const reportedBoost = React.useRef(false)
  const onBoostChangeRef = React.useRef(onBoostChange)
  useIsomorphicLayoutEffect(() => {
    onBoostChangeRef.current = onBoostChange
  })
  React.useEffect(() => {
    if (reportedBoost.current === boost) return
    reportedBoost.current = boost
    onBoostChangeRef.current?.(boost)
  }, [boost])

  const parts = React.Children.toArray(children)
  const adds = parts.filter((c) => React.isValidElement(c) && c.type === ComposerAdd)
  const above = parts.filter((c) => !adds.includes(c))

  const send = () => {
    const text = composerSendText(value)
    if (text === null) {
      fieldRef.current?.focus()
      return
    }
    onSend?.(text, { boost })
    setValue('')
    setDeclinedFor(null)
    fieldRef.current?.focus()
  }

  const hasText = value.trim() !== ''
  const talk = !small && !hasText && !!onVoice
  const buttonLabel = talk ? voiceLabel : sendLabel
  const name = fieldLabel ?? (placeholder || 'message')

  const onKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement | HTMLInputElement>) => {
    if (event.key === 'Escape') {
      /* Leave the field; the part around it may act on the key too. */
      event.currentTarget.blur()
      return
    }
    if (!composerKeySends(event.key, { shiftKey: event.shiftKey && !small, isComposing: event.nativeEvent.isComposing })) return
    event.preventDefault()
    event.currentTarget.form?.requestSubmit()
  }

  const field = small ? (
    <input
      ref={fieldRef as React.Ref<HTMLInputElement>}
      type="text"
      className="sl-composer-field"
      aria-label={name}
      placeholder={placeholder}
      value={value}
      onChange={(event) => setValue(event.target.value)}
      onKeyDown={onKeyDown}
    />
  ) : (
    <span className="sl-composer-field-box">
      {/* The placeholder is drawn over the empty field, not by the
          textarea: a textarea wraps its placeholder in a narrow field,
          while this one stays on one line and ends in an ellipsis. */}
      <textarea
        ref={fieldRef as React.Ref<HTMLTextAreaElement>}
        className="sl-composer-field"
        rows={1}
        aria-label={name}
        aria-placeholder={placeholder || undefined}
        value={value}
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={onKeyDown}
      />
      {value === '' && placeholder ? (
        <span className="sl-composer-placeholder" aria-hidden="true">
          {placeholder}
        </span>
      ) : null}
    </span>
  )

  const button = (
    <Tooltip label={buttonLabel} side="top">
      <PrimaryButton
        type={talk ? 'button' : 'submit'}
        className="sl-composer-send"
        aria-label={buttonLabel}
        data-mode={talk ? 'talk' : 'send'}
        onClick={talk ? () => onVoice?.() : undefined}
      >
        <Icon name={talk ? 'voice' : 'arrowUp'} size={small ? 16 : 18} />
      </PrimaryButton>
    </Tooltip>
  )

  return (
    <form
      ref={ref}
      className={cx('sl-composer', className)}
      data-size={size}
      data-tools={tools}
      data-has-text={hasText ? '' : undefined}
      autoComplete="off"
      onSubmit={(event) => {
        event.preventDefault()
        send()
      }}
      {...props}
    >
      {crossing !== undefined ? <div className="sl-composer-crossing">{crossing}</div> : null}
      {above}
      {!small && persona !== undefined ? <span className="sl-composer-writer">{persona}</span> : null}
      <div className="sl-composer-bar">
        {tools === 'always' ? adds : null}
        {field}
        <span className="sl-composer-tools">
          {tools === 'on focus' ? adds : null}
          {actions}
          {onDictate ? (
            <IconAction label="Dictate" tooltipSide="top" className="sl-composer-dictate" onClick={onDictate}>
              <Icon name="mic" />
            </IconAction>
          ) : null}
          {button}
        </span>
      </div>
      {boost ? (
        <p className="sl-composer-boost" role="status">
          thinks harder on this one
          <Verb className="sl-composer-boost-off" onClick={() => setDeclinedFor(value)}>
            do not
          </Verb>
        </p>
      ) : null}
    </form>
  )
}

export interface ComposerAddProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children'> {
  /* The icon's name and tooltip. */
  label?: string
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  /* Menu parts: what can be added (a file, a picture, a pointer). */
  children?: React.ReactNode
}

/* The `+` at the left of the field: a menu of what can ride along with
   the message. Place it among the Composer's children. */
function ComposerAdd({ label = 'Add', open, defaultOpen, onOpenChange, className, children, ...props }: ComposerAddProps) {
  return (
    <Menu open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>
      <Menu.Trigger asChild>
        <IconAction label={label} tooltipSide="top" className={cx('sl-composer-add', className)} {...props}>
          <Icon name="plus" />
        </IconAction>
      </Menu.Trigger>
      <Menu.Content side="top" align="start" aria-label={label}>
        {children}
      </Menu.Content>
    </Menu>
  )
}

export interface ComposerCarryProps extends React.ComponentPropsWithRef<'div'> {}

/* What travels with the next message: quoted pointers and attached files. */
function ComposerCarry({ className, ...props }: ComposerCarryProps) {
  return <div className={cx('sl-composer-carry', className)} {...props} />
}

interface RemoveProps {
  /* Shows the drop icon. */
  onRemove?: () => void
  removeLabel?: string
}

function RemoveButton({ onRemove, removeLabel = 'Drop' }: RemoveProps) {
  if (!onRemove) return null
  return (
    <Tooltip label={removeLabel}>
      <button type="button" className="sl-composer-remove" aria-label={removeLabel} onClick={onRemove}>
        <Icon name="x" size={12} />
      </button>
    </Tooltip>
  )
}

export interface ComposerPointerProps extends React.ComponentPropsWithRef<'span'>, RemoveProps {
  /* Whose words are quoted. */
  who: React.ReactNode
}

/* A quoted pointer: who said it and the words, on one line. */
function ComposerPointer({ who, onRemove, removeLabel, className, children, ...props }: ComposerPointerProps) {
  return (
    <span className={cx('sl-composer-pointer', className)} {...props}>
      <span className="sl-composer-pointer-who">{who}</span>
      <span className="sl-composer-pointer-text">{children}</span>
      <RemoveButton onRemove={onRemove} removeLabel={removeLabel} />
    </span>
  )
}

export interface ComposerChipProps extends React.ComponentPropsWithRef<'span'>, RemoveProps {
  /* The attached thing's kind. */
  icon: IconName
}

/* An attached file or selection: its kind, its name, and drop. */
function ComposerChip({ icon, onRemove, removeLabel, className, children, ...props }: ComposerChipProps) {
  return (
    <span className={cx('sl-composer-chip', className)} {...props}>
      <Icon name={icon} size={13} />
      <span>{children}</span>
      <RemoveButton onRemove={onRemove} removeLabel={removeLabel} />
    </span>
  )
}

export type ComposerPersonaKind = 'all' | 'work' | 'personal' | 'dream'

export interface ComposerPersonaProps extends React.ComponentPropsWithRef<'button'> {
  /* Which persona the writer writes as; each has its own portrait mark. */
  persona?: ComposerPersonaKind
  /* The writer's initial. */
  initial: string
  /* Who writes and where it is kept, as the portrait's tooltip: `You write
     as Owen. Saved in Antevon's vault.` */
  note?: string
}

/* The writer's portrait in the gutter at the left of the box: the active
   persona, 24 px. Make it a Menu.Trigger to pick another. */
function ComposerPersona({ ref, persona = 'all', initial, note, className, type = 'button', ...props }: ComposerPersonaProps) {
  const portrait = (
    <button ref={ref} type={type} className={cx('sl-composer-persona', className)} data-persona={persona} {...props}>
      <span aria-hidden="true">{initial}</span>
    </button>
  )
  return note ? (
    <Tooltip label={note} side="top" align="start">
      {portrait}
    </Tooltip>
  ) : (
    portrait
  )
}

/* Compound parts: Composer, .Add, .Carry, .Pointer, .Chip, .Persona. */
export const Composer = Object.assign(ComposerRoot, {
  Add: ComposerAdd,
  Carry: ComposerCarry,
  Pointer: ComposerPointer,
  Chip: ComposerChip,
  Persona: ComposerPersona,
})

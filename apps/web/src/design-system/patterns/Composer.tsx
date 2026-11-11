import * as React from 'react'
import { Icon, type IconName } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { PrimaryButton } from '../primitives/PrimaryButton'
import { Verb } from '../primitives/Verb'
import { Menu } from '../overlays/Menu'
import { Tooltip } from '../overlays/Tooltip'
import { cx, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { findBoostWord } from './find-boost-word'

/* The field grows with its text up to this height, then scrolls. */
const FIELD_MAX_PX = 220

export interface ComposerSendDetails {
  /* The text held a boost word and the person left the boost on. */
  boost: boolean
}

export interface ComposerProps extends Omit<React.ComponentPropsWithRef<'form'>, 'onSubmit' | 'defaultValue'> {
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
  /* Called with the trimmed text on Send and on Enter. */
  onSend?: (text: string, details: ComposerSendDetails) => void
  placeholder?: string
  /* The writer's portrait button, at the left of the field. */
  persona?: React.ReactNode
  /* Further tool icons at the right of the field, before the microphone. */
  actions?: React.ReactNode
  /* Shows the microphone: dictation into the field. */
  onDictate?: () => void
  /* While the field is empty, the send button becomes `Talk` and calls this. */
  onVoice?: () => void
  sendLabel?: string
  voiceLabel?: string
  /* The field's accessible name. */
  fieldLabel?: string
  /* One quiet line under the field: where the message is kept. */
  savedIn?: React.ReactNode
  /* Words that ask for more thought on a message. While the text holds one
     as a whole word, a quiet line says so, with `do not` to turn it off
     until the text changes. */
  boostWords?: readonly string[]
  onBoostChange?: (boost: boolean) => void
}

/* The write box. Children sit above the field: the outside line, then
   Composer.Carry with quoted pointers and attached chips; a Composer.Add
   among them sits at the left of the field instead, after the persona.
   One row: persona, add, the field (it grows to several lines), the tool
   icons, the microphone, then the one filled button (an arrow, `Send`; or
   `Talk` while the field is empty and voice is on). Enter sends,
   Shift+Enter starts a new line; an empty send puts focus in the field. */
function ComposerRoot({
  ref,
  value: valueProp,
  defaultValue = '',
  onValueChange,
  onSend,
  placeholder = 'Write a message',
  persona,
  actions,
  onDictate,
  onVoice,
  sendLabel = 'Send',
  voiceLabel = 'Talk',
  fieldLabel = 'message',
  savedIn,
  boostWords,
  onBoostChange,
  className,
  children,
  ...props
}: ComposerProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  const fieldRef = React.useRef<HTMLTextAreaElement | null>(null)

  /* Grow with the text: measure at auto height, keep within the maximum.
     Empty, the field is one line. */
  useIsomorphicLayoutEffect(() => {
    const field = fieldRef.current
    if (!field) return
    if (!value) {
      field.style.height = ''
      field.style.overflowY = 'hidden'
      return
    }
    field.style.height = 'auto'
    const next = Math.min(field.scrollHeight, FIELD_MAX_PX)
    field.style.height = `${next}px`
    field.style.overflowY = field.scrollHeight > FIELD_MAX_PX ? 'auto' : 'hidden'
  }, [value])

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
    const text = value.trim()
    if (!text) {
      fieldRef.current?.focus()
      return
    }
    onSend?.(text, { boost })
    setValue('')
    setDeclinedFor(null)
    fieldRef.current?.focus()
  }

  const talk = !value.trim() && !!onVoice
  const buttonLabel = talk ? voiceLabel : sendLabel

  return (
    <form
      ref={ref}
      className={cx('sl-composer', className)}
      autoComplete="off"
      onSubmit={(event) => {
        event.preventDefault()
        send()
      }}
      {...props}
    >
      {above}
      <div className="sl-composer-bar">
        {persona}
        {adds}
        {/* The placeholder is drawn over the empty field, not by the
            textarea: a textarea wraps its placeholder in a narrow field,
            while this one stays on one line and ends in an ellipsis. */}
        <span className="sl-composer-field-box">
          <textarea
            ref={fieldRef}
            className="sl-composer-field"
            rows={1}
            aria-label={fieldLabel}
            aria-placeholder={placeholder || undefined}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => {
              if (event.key !== 'Enter' || event.shiftKey || event.nativeEvent.isComposing) return
              event.preventDefault()
              event.currentTarget.form?.requestSubmit()
            }}
          />
          {value === '' && placeholder ? (
            <span className="sl-composer-placeholder" aria-hidden="true">
              {placeholder}
            </span>
          ) : null}
        </span>
        {actions}
        {onDictate ? (
          <IconAction label="Dictate" tooltipSide="top" className="sl-composer-dictate" onClick={onDictate}>
            <Icon name="mic" />
          </IconAction>
        ) : null}
        <Tooltip label={buttonLabel} side="top">
          <PrimaryButton
            type={talk ? 'button' : 'submit'}
            className="sl-composer-send"
            aria-label={buttonLabel}
            data-mode={talk ? 'talk' : 'send'}
            onClick={talk ? () => onVoice?.() : undefined}
          >
            <Icon name={talk ? 'voice' : 'arrowUp'} size={18} />
          </PrimaryButton>
        </Tooltip>
      </div>
      {savedIn !== undefined || boost ? (
        <div className="sl-composer-foot">
          {savedIn !== undefined ? <p className="sl-composer-saved">{savedIn}</p> : null}
          {boost ? (
            <p className="sl-composer-boost" role="status">
              thinks harder on this one
              <Verb className="sl-composer-boost-off" onClick={() => setDeclinedFor(value)}>
                do not
              </Verb>
            </p>
          ) : null}
        </div>
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
}

/* The writer's portrait at the left of the field: the active persona. Make
   it a Menu.Trigger to pick another. */
function ComposerPersona({ ref, persona = 'all', initial, className, type = 'button', ...props }: ComposerPersonaProps) {
  return (
    <button ref={ref} type={type} className={cx('sl-composer-persona', className)} data-persona={persona} {...props}>
      <span aria-hidden="true">{initial}</span>
    </button>
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

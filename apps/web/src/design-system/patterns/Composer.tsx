import * as React from 'react'
import { Icon, type IconName } from '../primitives/Icon'
import { PrimaryButton } from '../primitives/PrimaryButton'
import { Tooltip } from '../overlays/Tooltip'
import { cx, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'

/* The field grows with its text up to this height, then scrolls. */
const FIELD_MAX_PX = 220

export interface ComposerProps extends Omit<React.ComponentPropsWithRef<'form'>, 'onSubmit' | 'defaultValue'> {
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
  /* Called with the trimmed text on Send and on Enter. */
  onSend?: (text: string) => void
  placeholder?: string
  /* The writer's portrait button, at the left of the field. */
  persona?: React.ReactNode
  /* IconActions between the field and Send (attach). */
  actions?: React.ReactNode
  sendLabel?: string
  /* The field's accessible name. */
  fieldLabel?: string
}

/* The write box. Children sit above the field: the outside line, then
   Composer.Carry with quoted pointers and attached chips. Enter sends,
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
  sendLabel = 'Send',
  fieldLabel = 'message',
  className,
  children,
  ...props
}: ComposerProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  const fieldRef = React.useRef<HTMLTextAreaElement | null>(null)

  /* Grow with the text: measure at auto height, keep within the maximum. */
  useIsomorphicLayoutEffect(() => {
    const field = fieldRef.current
    if (!field) return
    field.style.height = 'auto'
    const next = Math.min(field.scrollHeight, FIELD_MAX_PX)
    field.style.height = `${next}px`
    field.style.overflowY = field.scrollHeight > FIELD_MAX_PX ? 'auto' : 'hidden'
  }, [value])

  const send = () => {
    const text = value.trim()
    if (!text) {
      fieldRef.current?.focus()
      return
    }
    onSend?.(text)
    setValue('')
    fieldRef.current?.focus()
  }

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
      {children}
      <div className="sl-composer-bar">
        {persona}
        <textarea
          ref={fieldRef}
          className="sl-composer-field"
          rows={1}
          aria-label={fieldLabel}
          placeholder={placeholder}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key !== 'Enter' || event.shiftKey || event.nativeEvent.isComposing) return
            event.preventDefault()
            event.currentTarget.form?.requestSubmit()
          }}
        />
        {actions}
        <PrimaryButton type="submit">{sendLabel}</PrimaryButton>
      </div>
    </form>
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

/* Compound parts: Composer, .Carry, .Pointer, .Chip, .Persona. */
export const Composer = Object.assign(ComposerRoot, {
  Carry: ComposerCarry,
  Pointer: ComposerPointer,
  Chip: ComposerChip,
  Persona: ComposerPersona,
})

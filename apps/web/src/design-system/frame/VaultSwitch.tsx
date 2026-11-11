import * as React from 'react'
import { Menu } from '../overlays/Menu'
import { StatusDot } from '../marks/StatusDot'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { cx, useControllableState } from '../lib/react-utils'

export interface VaultSwitchVault {
  id: string
  name: string
  /* A short word after the name in a quieter ink. */
  caption?: string
  /* How many things in that vault wait on the person: a ring and the
     count as a figure. */
  needsYou?: number
}

export interface VaultSwitchProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children' | 'onChange'> {
  vaults: VaultSwitchVault[]
  currentId?: string
  defaultCurrentId?: string
  onSwitch?: (id: string) => void
  /* With a handler the menu offers a new vault. */
  onCreate?: () => void
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  /* Further Menu parts under a separator: personas, devices, appearance,
     sign out. */
  children?: React.ReactNode
  /* An element to open the menu in place of the name and chevron (a
     MicroSidebar.Item); the rest of the props go onto it. */
  trigger?: React.ReactElement
}

/* The control at the top left: the current vault's name and a chevron. It
   opens a menu of the person's vaults (a pick each; one that waits on the
   person shows a ring and a count), a new vault, and the caller's parts. */
export function VaultSwitch({
  vaults,
  currentId: currentProp,
  defaultCurrentId,
  onSwitch,
  onCreate,
  open,
  defaultOpen,
  onOpenChange,
  className,
  children,
  trigger,
  ...props
}: VaultSwitchProps) {
  const [currentId, setCurrentId] = useControllableState(currentProp, defaultCurrentId ?? vaults[0]?.id, onSwitch)
  const current = vaults.find((v) => v.id === currentId) ?? vaults[0]
  return (
    <Menu open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>
      {trigger ? (
        <Menu.Trigger asChild className={className} {...props}>
          {trigger}
        </Menu.Trigger>
      ) : (
        <Menu.Trigger className={cx('sl-vault-switch', className)} {...props}>
          <span className="sl-vault-switch-name">{current?.name}</span>
          <svg className="sl-vault-switch-chevron" viewBox="0 0 10 10" aria-hidden="true" focusable="false">
            <path d="M2 3.5 L5 6.5 L8 3.5" />
          </svg>
        </Menu.Trigger>
      )}
      <Menu.Content width="wide" aria-label="vaults" className="sl-vault-switch-menu">
        <Menu.Heading>Vaults</Menu.Heading>
        {vaults.map((vault) => (
          <Menu.Item
            key={vault.id}
            className="sl-vault-switch-item"
            checked={vault.id === current?.id}
            onClick={() => setCurrentId(vault.id)}
          >
            <span className="sl-vault-switch-item-name">{vault.name}</span>
            <span className="sl-vault-switch-item-caption">{vault.caption}</span>
            {vault.needsYou ? (
              <span className="sl-vault-switch-item-needs">
                <StatusDot state="waiting" label={`${vault.needsYou} waiting on you`} />
                <Figure>{vault.needsYou}</Figure>
              </span>
            ) : null}
          </Menu.Item>
        ))}
        {onCreate ? (
          <Menu.Item icon={<Icon name="plus" />} onClick={onCreate}>
            new vault
          </Menu.Item>
        ) : null}
        {children ? (
          <>
            <Menu.Separator />
            {children}
          </>
        ) : null}
      </Menu.Content>
    </Menu>
  )
}

/* The Safelight component library. Styles: link design-system.css (one
   sheet that imports the tokens and every component's CSS). */

export { SafelightRoot, type SafelightRootProps } from './ground/SafelightRoot'
export { Field, type FieldProps } from './ground/Field'
export { Island, type IslandProps } from './ground/Island'
export { Well, type WellProps } from './ground/Well'

export { Verb, type VerbProps } from './primitives/Verb'
export { IconAction, type IconActionProps } from './primitives/IconAction'
export { PrimaryButton, type PrimaryButtonProps } from './primitives/PrimaryButton'
export { Figure, type FigureProps } from './primitives/Figure'
export { Tabs, type TabsProps, type TabsListProps, type TabsTabProps, type TabsPanelProps } from './primitives/Tabs'
export { Unfold, type UnfoldProps, type UnfoldTriggerProps, type UnfoldContentProps } from './primitives/Unfold'
export { Icon, ICON_NAMES, type IconName, type IconProps } from './primitives/Icon'

export { Tooltip, TOOLTIP_DELAY_MS, TOOLTIP_WARM_MS, type TooltipProps } from './overlays/Tooltip'
export {
  Popover,
  type PopoverProps,
  type PopoverTriggerProps,
  type PopoverContentProps,
} from './overlays/Popover'
export {
  Menu,
  type MenuContentProps,
  type MenuItemProps,
  type MenuHeadingProps,
  type MenuSeparatorProps,
  type MenuLineProps,
} from './overlays/Menu'

export { PickDiamond, type PickDiamondProps } from './marks/PickDiamond'
export { StatusDot, type StatusDotProps, type StatusDotState } from './marks/StatusDot'
export { GuestRing, type GuestRingProps } from './marks/GuestRing'
export { Seal, type SealProps, type SealAuthor } from './marks/Seal'
export { UrgencyMark, type UrgencyMarkProps } from './marks/UrgencyMark'
export { StepsBar, type StepsBarProps } from './marks/StepsBar'
export {
  stepsBarCells,
  stepsBarLabel,
  STEPS_BAR_MAX_SEGMENTS,
  STEPS_BAR_FIXED_CELLS,
  type Step,
  type StepState,
  type StepsBarCell,
  type StepsBarLayout,
} from './marks/steps-bar-cells'
export { Glyph, type GlyphProps, type GlyphState, type GlyphShape } from './marks/Glyph'
export { Portrait, type PortraitProps } from './marks/Portrait'

export {
  NeedsYou,
  NEEDS_YOU_UNDO_MS,
  type NeedsYouProps,
  type NeedsYouItemProps,
  type NeedsYouUrgency,
  type NeedsYouPicksProps,
  type NeedsYouPickProps,
  type NeedsYouOwnAnswerProps,
  type NeedsYouLaterProps,
  type NeedsYouCommandProps,
  type NeedsYouPlanProps,
  type NeedsYouStepProps,
  type NeedsYouContextProps,
} from './patterns/NeedsYou'
export {
  settleReducer,
  SETTLE_OPEN,
  type SettleState,
  type SettleAction,
  type SettleKind,
} from './patterns/settle-reducer'
export {
  MessageRow,
  type MessageRowProps,
  type MessageRowTextProps,
  type MessageRowAttachmentsProps,
  type MessageRowAttachmentProps,
  type MessageRowFoldProps,
  type MessageRowThreadLineProps,
  type MessageRowReactionsProps,
  type MessageRowReactionProps,
} from './patterns/MessageRow'
export { HoverBar, type HoverBarProps } from './patterns/HoverBar'
export { DayDivider, type DayDividerProps } from './patterns/DayDivider'
export { RunFoot, type RunFootProps, type RunFootCallProps, type RunSubState } from './patterns/RunFoot'
export { formatElapsed } from './patterns/run-elapsed'
export {
  CrewStack,
  type CrewStackProps,
  type CrewStackMemberProps,
  type CrewStackListProps,
  type CrewStackListRowProps,
} from './patterns/CrewStack'
export { SplitPane, type SplitPaneProps, type SplitPanePaneProps, type SplitPaneHandleProps } from './patterns/SplitPane'
export { snapToMagnet, SPLIT_MAGNETS, SPLIT_MAGNET_PULL_PX, type MagnetSnap } from './patterns/snap-to-magnet'
export {
  Composer,
  type ComposerProps,
  type ComposerCarryProps,
  type ComposerPointerProps,
  type ComposerChipProps,
  type ComposerPersonaProps,
  type ComposerPersonaKind,
} from './patterns/Composer'
export { OutsideLine, type OutsideLineProps, type OutsideLineGroupProps, type OutsideLineGuestProps } from './patterns/OutsideLine'
export { ConnectionRow, type ConnectionRowProps } from './patterns/ConnectionRow'
export { FileRow, type FileRowProps } from './patterns/FileRow'
export { FileGroup, type FileGroupProps } from './patterns/FileGroup'
export {
  LedgerTable,
  type LedgerTableProps,
  type LedgerTableHeadProps,
  type LedgerTableRowProps,
  type LedgerTableCellProps,
} from './patterns/LedgerTable'
export { ClaimText, type ClaimTextProps } from './patterns/ClaimText'
export { claimInk, type ClaimInk } from './patterns/claim-ink'

export { GLYPH_NAMES, type GlyphName } from './lib/seal-art'
export { placeFloating, anchorInViewport, type Side, type Align, type Placement, type PlacementOptions } from './lib/placement'
export { bayerThreshold, easeOutQuart, develop, BAYER_8X8 } from './lib/dither'
export { useResolvedScheme, resolveScheme, type Scheme } from './lib/scheme'
export { useControllableState, Slot, cx } from './lib/react-utils'

import { createFileRoute } from '@tanstack/react-router'
import { PaneHead, Sheet } from './-shared'

export const Route = createFileRoute('/settings/account')({
  component: AccountPage,
})

/* ── account: the person signed in. one row, one act. ── */
function AccountPage() {
  return (
    <Sheet page="account">
      <PaneHead title="account" hint="The person signed in. The vault stays where it is when you leave." />
      <div className="srow acct">
        <span className="seal seal-human" title="o · Owen · owner">
          o
        </span>
        <span className="val">Owen</span>
        <span className="addr" title="the account address">
          owen@example.com
        </span>
        <span className="acts tail">
          <a className="act" href="/signin" title="verb: sign_out · the vault stays where it is">
            sign out
          </a>
        </span>
      </div>
    </Sheet>
  )
}

import { Link } from '@tanstack/react-router'

/* the lost page (08-15 eve): the riso plate is the whole page — sun and
   flock by day, moon and flock by night — and the sheet is a small card */
export function NotFound({ children }: { children?: React.ReactNode }) {
  return (
    <div className="lost">
      <div className="lost-card">
        <span className="label">404</span>
        <span className="lost-title">Nothing here.</span>
        <span className="lost-line">{children ?? 'The page you asked for does not exist.'}</span>
        <div className="lost-acts">
          <button type="button" className="act" onClick={() => window.history.back()}>
            back
          </button>
          <Link to="/app/inbox" className="act">
            inbox
          </Link>
        </div>
      </div>
    </div>
  )
}

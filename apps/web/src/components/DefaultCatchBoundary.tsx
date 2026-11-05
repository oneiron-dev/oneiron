import { Link, useRouter } from '@tanstack/react-router'
import type { ErrorComponentProps } from '@tanstack/react-router'

/* the error page wears the lost page's shape (08-15 eve) */
export function DefaultCatchBoundary({ error }: ErrorComponentProps) {
  const router = useRouter()
  console.error('DefaultCatchBoundary Error:', error)
  return (
    <div className="lost">
      <div className="lost-card">
        <span className="label">error</span>
        <span className="lost-title">Something broke.</span>
        <span className="lost-line">The page hit an error. Try again, or go to the inbox.</span>
        <pre className="lost-err">{error instanceof Error ? error.message : String(error)}</pre>
        <div className="lost-acts">
          <button type="button" className="act" onClick={() => router.invalidate()}>
            try again
          </button>
          <Link to="/app/inbox" className="act">
            inbox
          </Link>
        </div>
      </div>
    </div>
  )
}

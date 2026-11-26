//! The wire's pulls: the calendar-wire entry and the read of the listing's
//! next page or the next page of changes after the cursor's token.

use super::*;

impl HttpCalDavCalendarWire<'_> {
    /// One pull through the open `account`: the listing's next page, or the
    /// next page of changes after the cursor's token.
    fn read(
        &self,
        account: &Account<'_>,
        source: &MailSyncSource,
        wanted: Option<&str>,
        cursor: Option<CalDavCursor>,
    ) -> Result<MailCalendarRead> {
        let cursor = match cursor {
            Some(cursor) => cursor,
            None => {
                let calendar = account.discover(wanted)?;
                let token = account.sync_token(&calendar)?;
                CalDavCursor {
                    calendar: calendar.to_string(),
                    token,
                    listed: Some(String::new()),
                    round: None,
                }
            }
        };
        let calendar = account.url(&cursor.calendar)?;
        let page = if let Some(after) = &cursor.listed {
            list_page(account, &calendar, cursor.token.clone(), after)?
        } else {
            match self.changes(account, source, &calendar, cursor)? {
                Some(page) => page,
                None => return Ok(MailCalendarRead::Expired),
            }
        };
        Ok(MailCalendarRead::Pull(MailCalendarPull {
            changes: page.changes,
            next_cursor: Some(
                serde_json::to_string(&page.next)
                    .map_err(|_| refused("caldav_calendar_cursor_unencodable"))?,
            ),
            complete: page.complete,
            covers: None,
            vacated: page.vacated,
        }))
    }

    /// The next page of changes after the cursor's token, at most
    /// `CHANGES_PAGE` members: the changed members first, then the removed
    /// ones, each in href order, so every event a round reads has landed
    /// before any member it removes is settled. A removed member's landed
    /// UID is deleted: the provider's tombstone. A UID a changed member held
    /// before it holds another or none is vacated: marked absent, as a
    /// finished listing marks one it omitted, so a later page that reads it
    /// under another member lands it live again. A UID read again under
    /// another member, on this page or landed under one that keeps it, is
    /// neither: its old member's row is retired. A round over more pages
    /// than one goes on from its last member under the same token, and ends
    /// on the token its first page answered, so a change made while it ran
    /// is read again. `None` when the server no longer honours the token.
    fn changes(
        &self,
        account: &Account<'_>,
        source: &MailSyncSource,
        calendar: &Url,
        cursor: CalDavCursor,
    ) -> Result<Option<Page>> {
        let Some(synced) = account.sync(calendar, &cursor.token)? else {
            return Ok(None);
        };
        let (after, round_token) = match cursor.round {
            Some(round) => ((round.removed, round.after), round.token),
            None => ((false, String::new()), synced.token.clone()),
        };
        let removed: BTreeSet<String> = synced.removed.into_iter().collect();
        let members: BTreeSet<(bool, String)> = synced
            .changed
            .into_iter()
            .filter(|href| !removed.contains(href))
            .map(|href| (false, href))
            .chain(removed.iter().map(|href| (true, href.clone())))
            .collect();
        let (page, more) = page_after(&members, &after, CHANGES_PAGE);
        let read = self.page_changes(account, source, calendar, &page)?;
        let (changes, vacated) = self.settle(source, read)?;
        let next = if more {
            let (in_removed, after) = page.last().cloned().unwrap_or(after);
            CalDavCursor {
                calendar: calendar.to_string(),
                token: cursor.token,
                listed: None,
                round: Some(ChangeRound {
                    after,
                    removed: in_removed,
                    token: round_token,
                }),
            }
        } else {
            CalDavCursor {
                calendar: calendar.to_string(),
                token: round_token,
                listed: None,
                round: None,
            }
        };
        Ok(Some(Page {
            changes,
            vacated,
            next,
            complete: !more && !synced.truncated,
        }))
    }
}

impl MailCalendarWire for HttpCalDavCalendarWire<'_> {
    fn pull(&self, source: &MailSyncSource, cursor: Option<&str>) -> Result<MailCalendarRead> {
        if source.provider != MailProvider::Caldav {
            return Err(refused("caldav_calendar_wire_reads_caldav_sources_only"));
        }
        let mut cursor: Option<CalDavCursor> = cursor
            .map(|cursor| {
                serde_json::from_str(cursor)
                    .map_err(|_| refused("caldav_calendar_cursor_unreadable"))
            })
            .transpose()?;
        let mut read: Option<MailCalendarRead> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Calendar,
            CALDAV_CALENDAR_CONNECTOR_EFFECTOR,
            &mut |secret: &[u8]| {
                let (account, wanted) = Account::open(&self.client, secret, source)?;
                read = Some(self.read(&account, source, wanted.as_deref(), cursor.take())?);
                Ok(())
            },
        )?;
        read.ok_or_else(|| refused("caldav_calendar_credential_door_refused"))
    }
}

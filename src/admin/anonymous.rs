/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

use super::auth::ClientKey;

pub const MAX_ANONYMOUS_CONNECTIONS: usize = 32;

#[derive(Default)]
pub struct Anonymous {
    queue: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    next: u64,
    held: VecDeque<Held>,
}

struct Held {
    id: u64,
    key: ClientKey,
    evict: Arc<Notify>,
}

impl Queue {
    fn evict_from_busiest(&mut self) {
        let count = |key: ClientKey| self.held.iter().filter(|held| held.key == key).count();
        let Some(victim) = self
            .held
            .iter()
            .map(|held| (count(held.key), held.id))
            .reduce(|best, next| if next.0 > best.0 { next } else { best })
            .map(|(_, id)| id)
        else {
            return;
        };
        self.held.retain(|held| match held.id == victim {
            true => {
                held.evict.notify_one();
                false
            }
            false => true,
        });
    }
}

pub struct Ticket {
    id: u64,
    evict: Arc<Notify>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admission {
    Free,
    Evicted,
}

impl Anonymous {
    pub fn admit(&self, key: ClientKey) -> (Ticket, Admission) {
        let evict = Arc::new(Notify::new());
        let mut queue = self.queue.lock();
        let admission = match queue.held.len() >= MAX_ANONYMOUS_CONNECTIONS {
            true => {
                queue.evict_from_busiest();
                Admission::Evicted
            }
            false => Admission::Free,
        };
        let id = queue.next;
        queue.next = id.wrapping_add(1);
        queue.held.push_back(Held {
            id,
            key,
            evict: evict.clone(),
        });
        (Ticket { id, evict }, admission)
    }

    pub fn release(&self, ticket: &Ticket) {
        self.queue.lock().held.retain(|held| held.id != ticket.id);
    }
}

impl Ticket {
    pub async fn unless_evicted<F: Future>(ticket: Option<&Ticket>, work: F) -> Option<F::Output> {
        match ticket {
            Some(ticket) => tokio::select! {
                output = work => Some(output),
                () = ticket.evict.notified() => None,
            },
            None => Some(work.await),
        }
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/admin/anonymous/tests.rs"]
mod tests;

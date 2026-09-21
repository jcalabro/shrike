//! Drive archive I/O during sink delivery without spawning the !Send transport.

use futures::{StreamExt, future::poll_fn, stream::FuturesOrdered};
use std::{
    collections::VecDeque,
    future::Future,
    pin::pin,
    task::{Context, Poll},
};

pub(super) struct OrderedDownloads<I: Iterator>
where
    I::Item: Future,
{
    input: I,
    jobs: FuturesOrdered<I::Item>,
    ready: VecDeque<<I::Item as Future>::Output>,
    limit: usize,
    exhausted: bool,
    current: bool,
}

impl<I: Iterator> OrderedDownloads<I>
where
    I::Item: Future,
{
    pub(super) fn new(input: I, limit: usize) -> Self {
        Self {
            input,
            jobs: FuturesOrdered::new(),
            ready: VecDeque::new(),
            limit: limit.max(1),
            exhausted: false,
            current: false,
        }
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) {
        while !self.exhausted
            && self.jobs.len() + self.ready.len() + usize::from(self.current) < self.limit
        {
            match self.input.next() {
                Some(job) => self.jobs.push_back(job),
                None => self.exhausted = true,
            }
        }
        // Completed jobs still occupy their bounded slot until consumed. Count
        // the segment currently being delivered too, so a slow sink cannot
        // turn concurrency into unbounded buffering.
        while let Poll::Ready(Some(result)) = self.jobs.poll_next_unpin(cx) {
            self.ready.push_back(result);
        }
    }

    pub(super) async fn next(&mut self) -> Option<<I::Item as Future>::Output> {
        self.current = false;
        poll_fn(|cx| {
            self.poll_progress(cx);
            if let Some(result) = self.ready.pop_front() {
                self.current = true;
                Poll::Ready(Some(result))
            } else if self.exhausted && self.jobs.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        })
        .await
    }

    pub(super) async fn during<F: Future>(&mut self, delivery: F) -> F::Output {
        let mut delivery = pin!(delivery);
        poll_fn(|cx| {
            self.poll_progress(cx);
            delivery.as_mut().poll(cx)
        })
        .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn preserves_order_and_bounds_even_with_a_slow_consumer() {
        futures::executor::block_on(async {
            let started = Rc::new(Cell::new(0));
            let mut downloads = OrderedDownloads::new(
                (0..20).map(|i| {
                    let started = started.clone();
                    async move {
                        started.set(started.get() + 1);
                        i
                    }
                }),
                3,
            );
            assert_eq!(downloads.next().await, Some(0));
            assert_eq!(started.get(), 3);
            for _ in 0..10 {
                downloads.during(std::future::ready(())).await;
            }
            assert_eq!(
                started.get(),
                3,
                "ready results and current delivery retain slots"
            );
            for i in 1..20 {
                assert_eq!(downloads.next().await, Some(i));
            }
            assert_eq!(downloads.next().await, None);
        });
    }

    #[test]
    fn pending_download_makes_progress_while_sink_waits() {
        futures::executor::block_on(async {
            let (sent, received) = futures::channel::oneshot::channel();
            let mut sent = Some(sent);
            let mut downloads = OrderedDownloads::new(
                (0..2).map(|i| {
                    let sent = if i == 1 { sent.take() } else { None };
                    async move {
                        if let Some(sent) = sent {
                            // Require another poll after initial download setup.
                            let mut yielded = false;
                            poll_fn(|cx| {
                                if yielded {
                                    Poll::Ready(())
                                } else {
                                    yielded = true;
                                    cx.waker().wake_by_ref();
                                    Poll::Pending
                                }
                            })
                            .await;
                            sent.send(()).unwrap();
                        }
                        i
                    }
                }),
                2,
            );
            assert_eq!(downloads.next().await, Some(0));
            downloads.during(received).await.unwrap();
            assert_eq!(downloads.next().await, Some(1));
            assert_eq!(downloads.next().await, None);
        });
    }

    #[test]
    fn one_slot_does_not_start_another_segment_during_delivery() {
        futures::executor::block_on(async {
            let started = Rc::new(Cell::new(0));
            let mut downloads = OrderedDownloads::new(
                (0..3).map(|i| {
                    let started = started.clone();
                    async move {
                        started.set(started.get() + 1);
                        i
                    }
                }),
                1,
            );
            assert_eq!(downloads.next().await, Some(0));
            downloads.during(std::future::ready(())).await;
            assert_eq!(started.get(), 1);
            assert_eq!(downloads.next().await, Some(1));
        });
    }
}

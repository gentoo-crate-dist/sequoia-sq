use crossbeam::thread;
use crossbeam::channel::unbounded as channel;

const TRACE: bool = false;

/// Like `Iterator::filter_map`, but potentially parallel.
///
/// Unlike `rayon`, threads do not busy wait when they have nothing to
/// do.
///
/// `max_threads` is the maximum number of threads to start.  `None`
/// means unlimited.
///
/// The results are not guaranteed to be returned in the same order as
/// `items`.
pub fn par_filter_map_unordered<'a, N, T, U, F>(items: impl Iterator<Item=T> + 'a,
                                                max_threads: N,
                                                f: F)
    -> impl Iterator<Item=U> + 'a
where
    N: Into<Option<usize>>,
    T: Send + 'a,
    U: Send + 'a,
    F: Fn(T) -> Option<U> + Send + Sync + 'a,
{
    tracer!(TRACE, "par_filter_map");

    // Use not more threads than we have cores.  No point in
    // spawning a single thread, just do it inline.  Also, some
    // platforms don't support spawning threads.
    let mut threads = std::thread::available_parallelism()
        .map(|i| i.get())
        .unwrap_or(0);
    if threads <= 1 {
        threads = 0;
    }
    if let Some(max_threads) = max_threads.into() {
        if threads > max_threads {
            threads = max_threads;
        }
    }

    if threads == 0 {
        Box::new(items.filter_map(f)) as Box<dyn Iterator<Item=U>>
    } else {
        let result = thread::scope(|thread_scope| {
            let (work_tx, work_rx) = channel();
            let mut threads_extant = Vec::new();

            for item in items {
                if threads_extant.len() < threads {
                    let tid = threads_extant.len();
                    t!("Starting thread {} of {}",
                       tid, threads);

                    let mut work = Some(Ok(item));

                    // The thread's state.
                    let work_rx = work_rx.clone();

                    let f = &f;
                    threads_extant.push(thread_scope.spawn(move |_| {
                        let mut results: Vec<U> = Vec::new();

                        loop {
                            match work.take().unwrap_or_else(|| work_rx.recv()) {
                                Err(_) => break,
                                Ok(item) => {
                                    t!("Thread {} dequeuing item {}!",
                                       tid, results.len() + 1);
                                    if let Some(result) = f(item) {
                                        results.push(result);
                                    }
                                }
                            }
                        }

                        t!("Thread {} exiting (processed {} items)",
                           tid, results.len());

                        results
                    }));
                } else {
                    work_tx.send(item).unwrap();
                }
            }

            // When the threads see this drop, they will exit.
            drop(work_tx);

            let results = threads_extant.into_iter().flat_map(|t| {
                let result: Vec<U> = t.join().unwrap();
                result
            }).collect::<Vec<U>>();

            Box::new(results.into_iter()) as Box<dyn Iterator<Item=U>>
        }); // thread scope.

        result.expect("No threading error")
    }
}


/// Like `Iterator::map`, but potentially parallel.
///
/// Unlike `rayon`, threads do not busy wait when they have nothing to
/// do.
///
/// The results are not guaranteed to be returned in the same order as
/// `items`.
pub fn par_map_unordered<'a, N, T, U, F>(items: impl Iterator<Item=T> + 'a,
                                         max_threads: N,
                                         f: F)
    -> impl Iterator<Item=U> + 'a
where
    N: Into<Option<usize>>,
    T: Send + 'a,
    U: Send + 'a,
    F: Fn(T) -> U + Send + Sync + 'a,
{
    par_filter_map_unordered(
        items, max_threads.into(), move |item| Some(f(item)))
}

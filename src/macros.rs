macro_rules! platform {
    { unix => { $($unix:tt)* }, windows => { $($windows:tt)* }, } => {
        if cfg!(unix) {
            #[cfg(unix)] { $($unix)* }
            #[cfg(not(unix))] { unreachable!() }
        } else if cfg!(windows) {
            #[cfg(windows)] { $($windows)* }
            #[cfg(not(windows))] { unreachable!() }
        } else {
            #[cfg(not(any(unix, windows)))] compile_error!("Unsupported platform");
            unreachable!()
        }
    }
}

/// Like eprintln, but nicely wraps lines.
macro_rules! wprintln {
    {} => {
        eprintln!();
    };

    { indent=$i: expr, $($arg: expr),* } => {{
        let i = $i;
        crate::output::wrapping::iwprintln(i.as_ref(), i.as_ref(),
                                           format_args!($($arg),*))
    }};

    {
        initial_indent=$ii: expr,
        subsequent_indent=$si: expr,
        $($arg: expr),*
    } => {{
        let ii = $ii;
        let si = $si;
        crate::output::wrapping::iwprintln(ii.as_ref(), si.as_ref(),
                                           format_args!($($arg),*))
    }};

    { $($arg: expr),* } => {
        crate::output::wrapping::wprintln(format_args!($($arg),*))
    };
}

/// Like wprintln, but doesn't emit anything in quiet mode.
macro_rules! make_qprintln {
    ($quiet: expr) => {
        macro_rules! qprintln {
            {} => {
                if ! $quiet {
                    wprintln!();
                }
            };
            { $a0: expr } => {
                if ! $quiet {
                    wprintln!($a0);
                }
            };
            { $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3, $a4);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };
        }
    };
}

/// A very simple profiling tool.
///
/// Note: don't ever profile code that has not been compiled in
/// release mode.  There can be orders of magnitude difference in
/// execution time between it and debug mode!
///
/// This macro measures the wall time it takes to execute the block.
/// If the time is at least $ms_threshold (in milli-seconds), then it
/// displays the output on stderr.  The output is prefixed with label,
/// if it is provided.
///
/// ```nocompile
/// let result = time_it!("Some code", 10, {
///     // Some code.
///     5
/// });
/// assert_eq!(result, 5);
/// ```
#[allow(unused_macros)]
macro_rules! time_it {
    ( $label:expr, $ms_threshold:expr, $body:expr ) => {{
        use std::time::{SystemTime, Duration};

        // We use drop so that code that uses non-local exits (e.g.,
        // using break 'label) still works.
        struct Timer {
            start: SystemTime,
            label: String,
        }
        impl Drop for Timer {
            fn drop(&mut self) {
                let elapsed = self.start.elapsed();
                if elapsed.clone().unwrap_or(Duration::from_millis($ms_threshold))
                    >= Duration::from_millis($ms_threshold)
                {
                    if self.label.len() > 0 {
                        eprint!("{}:", self.label);
                    }
                    eprintln!("{}:{}: {:?}", file!(), line!(), elapsed);
                }
            }
        }

        let _start = Timer { start: SystemTime::now(), label: String::from($label), };
        $body
    }};
    ( $label:expr, $body:expr ) => {
        time_it!($label, 0, $body)
    };
    ( $body:expr ) => {
        time_it!("", $body)
    };
}

/// Generate the stream trait and some associated machinery.
///
/// This is used by all modules that implement a stream interface.
/// Ideally we'd have a top-level trait with type parameters for
/// Params and Output.  But if we do that then we can't implement
/// `Stream for &mut T`, because:
///
/// ```text
/// 197 | / impl<Params, Output, T> Stream<Params, Output> for &mut T
/// 198 | | where
/// 199 | |     T: Stream<Params, Output> + ?Sized
///     | |______________________________________- first implementation here
/// ...
/// 207 |   impl<Params, Output> Stream<Params, Output> for &mut Vec<Output> {
///     |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ conflicting implementation for `&mut Vec<_>`
/// ```
macro_rules! stream {
    {} => {
        /// The trait for collecting output.
        pub trait Stream<'sequoia> {
            /// Output.
            fn output(&mut self, params: &Params<'sequoia>, output: Output) -> Result<()>;
        }

        impl<'sequoia, T> Stream<'sequoia> for Box<T>
        where
            T: Stream<'sequoia> + ?Sized
        {
            fn output(&mut self, params: &Params<'sequoia>, output: Output) -> Result<()> {
                AsMut::as_mut(self).output(params, output)
            }
        }

        impl<'sequoia, T> Stream<'sequoia> for &mut T
        where
            T: Stream<'sequoia> + ?Sized
        {
            fn output(&mut self, params: &Params<'sequoia>, output: Output) -> Result<()> {
                (*self).output(params, output)
            }
        }

        /// Collects the output in the specified vector.
        impl<'sequoia> Stream<'sequoia> for &mut Vec<Output> {
            fn output(&mut self, _params: &Params<'sequoia>, output: Output) -> Result<()> {
                self.push(output);
                Ok(())
            }
        }

        /// Discards the output.
        impl<'sequoia> Stream<'sequoia> for () {
            fn output(&mut self, _params: &Params<'sequoia>, _output: Output) -> Result<()> {
                Ok(())
            }
        }

        impl<'sequoia, S> Stream<'sequoia> for Option<S>
        where
            S: Stream<'sequoia>
        {
            fn output(&mut self, params: &Params<'sequoia>, output: Output) -> Result<()> {
                if let Some(stream) = self.as_mut() {
                    stream.output(params, output)
                } else {
                    Ok(())
                }
            }
        }
    }
}

macro_rules! stream_builder_impl {
    () => {
        stream_builder_impl!(;);
    };
    ($($prelifetimes:lifetime),*; $($postlifetimes:lifetime),* $($generics:ident),*) => {
        /// Emits events on the specified stream.
        pub fn stream<'s, S>(self, stream: S)
            -> Builder<'sequoia,
                       $($prelifetimes,)*
                       's,
                       $($postlifetimes,)*
                       $($generics,)*>
        where
            S: Stream<'sequoia> + 's
        {
            Builder {
                params: Params {
                    ..self.params
                },
                params_once: ParamsOnce {
                    stream: Some(Box::new(stream)),
                    ..self.params_once
                },
                ..self
            }
        }
    }
}

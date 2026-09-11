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
    ($($prelifetimes:lifetime),*; $($postlifetimes:lifetime,)* $($generics:ident),*) => {
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

/// Add `prompt` and `prompt_` methods to a `Builder`.
macro_rules! prompt_builder_impl {
    () => {
        prompt_builder_impl!(;);
    };
    ($($prelifetimes:lifetime),*; $($postlifetimes:lifetime),* $($generics:ident),*) => {
        /// Sets the prompt implementation to use.
        ///
        /// This overrides prompt configured for the
        /// [`Sequoia`](crate::Sequoia::new) instance.
        pub fn prompt<'p, O, P>(self, prompt: O)
            -> Builder<'sequoia,
                       $($prelifetimes,)*
                       'p,
                       $($postlifetimes,)*
                       $($generics,)*>
        where
            O: Into<Option<P>>,
            P: $crate::prompt::PromptFactory<'p> + 'p,
        {
            let prompt = prompt.into();
            let prompt = prompt.map(|p| Arc::new(p) as Arc<_>);

            Builder {
                params_once: ParamsOnce {
                    prompt,
                    ..self.params_once
                },
                ..self
            }
        }

        /// A variant of `prompt`.
        ///
        /// This takes the raw type that we use internally.
        #[allow(unused)]
        pub(crate) fn prompt_<'p>(
            self,
            prompt: Option<std::sync::Arc<
                dyn crate::prompt::PromptFactory<'p> + 'p>>)
            -> Builder<'sequoia,
                       $($prelifetimes,)*
                       'p,
                       $($postlifetimes,)*
                       $($generics,)*>
        {
            Builder {
                params_once: ParamsOnce {
                    prompt,
                    ..self.params_once
                },
                ..self
            }
        }
    }
}

/// Displays a prompt.
///
/// If `$prompt` is `Some`, uses that prompt implementation.
/// Otherwise, uses the default implementation in `$sequoia`.
///
/// Note that `$prompt` and `$sequoia.prompt` have different
/// lifetimes so we **can't** do:
///
/// ```text
/// let prompt = if let Some(prompt) = prompt.as_ref() {
///     prompt
/// } else {
///     &sequoia.prompt
/// };
///
/// let result = prompt.prompt(...);
/// ```
macro_rules! prompt {
    ($sequoia:expr, $prompt:expr, $context:expr, $checker:expr) => {
        if let Some(prompt) = $prompt.as_ref() {
            prompt.prompt($context, $checker)
        } else {
            $sequoia.prompt.prompt($context, $checker)
        }
    }
}

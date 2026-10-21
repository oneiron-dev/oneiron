//! The Core ML worker's inputs (FIX 6755 slice 2c, contract rev 3 B2), on
//! every target: the trunk's raw word embedding table, and each call's
//! window as the compiled model reads it.
//!
//! The table is `encoder.embeddings.word_embeddings.weight` alone, from the
//! verified trunk, kept as float16: the model casts its input to float16
//! first, so a value rounded there is the value it sees. Only that lookup
//! happens here. Token type, position, the norm and every encoder layer
//! are the compiled model's; no backbone is built and nothing is run.
//!
//! A call's input is its window's token ids padded to its function's
//! tokens `L` with the row's pad id: `x` `[1, hidden, 1, L]` float32,
//! channel-first, element `(c, j)` token `j`'s embedding at channel `c`,
//! and `attention_mask` `[1, L]` int32, 1 for the window's tokens and 0
//! for the pad. Each checks its own shape; none caps a text or a size.

use candle_core::DType;
use candle_nn::VarBuilder;
use half::f16;

/// The trunk's word embedding table, `[vocab, hidden]`, its values float16.
pub(super) struct WordEmbeddings {
    table: Vec<f16>,
    vocab: usize,
    hidden: usize,
}

/// One call's inputs, each first-major in its function's shape.
pub(super) struct Inputs {
    /// `x`: `[1, hidden, 1, L]`.
    pub(super) x: Vec<f32>,
    /// `attention_mask`: `[1, L]`.
    pub(super) mask: Vec<i32>,
}

impl WordEmbeddings {
    /// Tensor `name` of the verified trunk's `weights`, which must be
    /// `[vocab, hidden]`, as float16. Every other tensor stays unread.
    pub(super) fn load(
        weights: &VarBuilder<'_>,
        name: &str,
        hidden: usize,
    ) -> anyhow::Result<Self> {
        let table = weights.get_unchecked_dtype(name, DType::F16)?;
        let (vocab, width) = table.dims2()?;
        anyhow::ensure!(
            vocab > 0 && width == hidden,
            "the trunk's word embeddings are not {hidden} wide"
        );
        let table = table.flatten_all()?.to_vec1::<f16>()?;
        Ok(Self {
            table,
            vocab,
            hidden,
        })
    }

    /// `ids` padded to `tokens` with `pad`, as the module says. A window
    /// longer than its function, or a token outside the table, fails.
    pub(super) fn prepare(&self, ids: &[u32], tokens: usize, pad: u32) -> anyhow::Result<Inputs> {
        anyhow::ensure!(
            ids.len() <= tokens,
            "a window is longer than its core ml function"
        );
        let mut x = vec![0.0_f32; self.hidden * tokens];
        let mut mask = vec![0_i32; tokens];
        for (column, held) in mask.iter_mut().enumerate() {
            let id = match ids.get(column) {
                Some(&id) => {
                    *held = 1;
                    id
                }
                None => pad,
            };
            for (channel, value) in self.row(id)?.iter().enumerate() {
                x[channel * tokens + column] = value.to_f32();
            }
        }
        Ok(Inputs { x, mask })
    }

    /// Token `id`'s embedding.
    fn row(&self, id: u32) -> anyhow::Result<&[f16]> {
        let id = usize::try_from(id)?;
        anyhow::ensure!(id < self.vocab, "a token is outside the word embeddings");
        let start = id * self.hidden;
        Ok(&self.table[start..start + self.hidden])
    }
}
